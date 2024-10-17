local stdnse    = require "stdnse"
local smb       = require "smb"
local smb2      = require "smb2"
local msrpc     = require "msrpc"
local bin       = require "bin"
local shortport = require "shortport"

description = [[
Return free and total size in octets of each SMB shares
]]

---
-- @args See the documentation for the smbauth library.
--
-- @usage nmap -p137-139,445 --script smb-shares-size.nse --script-args-file smb-authentication.ini <host>
--
-- @output
-- Host script results:
-- | smb-shares-size:
-- |   data:
-- |     FreeSize: 38495883264
-- |     TotalSize: 500961574912
-- |_  IPC$: NT_STATUS_ACCESS_DENIED
---

categories = {"discovery", "intrusive"}
author = "Adrien Malingrey"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

portrule = shortport.service({"microsoft-ds", "netbios-ssn", "smb"})


action = function(host)
  local status, shares, extra
  local response = stdnse.output_table()

  -- Try and do this the good way, make a MSRPC call to get the shares
  stdnse.debug1("SMB: Attempting to log into the system to enumerate shares")
  status, shares = msrpc.enum_shares(host)
  if(status == false) then
    return stdnse.format_output(false, string.format("Couldn't enumerate shares: %s", shares))
  end

  -- Get more information on each share
  for i = 1, #shares, 1 do
    local share = shares[i]
    if (share ~= nil) then
      local status, result = get_share_info(host, share)
      if (status) then
        response[share] = result
      end
    end
  end

  return response
end

TRANS2_QUERY_FS_INFORMATION = 0x0003
SMB_QUERY_FS_SIZE_INFO      = 0x0103
---Attempts to retrieve additional information about a share. Will fail unless we have
-- administrative access.
--
--@param host The host object.
--@return Status (true or false).
--@return A table of information about the share (if status is true) or an an error string (if
--        status is false).
function get_share_info(host, share)
  local status, smbstate, err
  local hostaddress = (host.name ~= '' and host.name) or host.ip
  local path = "\\\\" .. hostaddress .. "\\" .. share

  status, smbstate = smb.start(host)
  status, err      = smb.negotiate_protocol(smbstate, {})
  status, err      = smb.start_session(smbstate, {})
  status, err      = smb.tree_connect(smbstate, path, {})
  
  stdnse.debug1("SMB: Getting information for share: %s", path)
  
  local status, err = send_transaction2(smbstate, TRANS2_QUERY_FS_INFORMATION, bin.pack("<S", SMB_QUERY_FS_SIZE_INFO))
  if ( not(status) ) then
    status, err      = smb.stop(smbstate)
    return false, "Failed to send data to server: send_transaction2"
  end

  local status, response = receive_transaction2(smbstate)
  if ( not(status) ) then
    status, err      = smb.stop(smbstate)
    return false, response
  end

  local pos, totalAllocationUnits, totalFreeAllocationUnits, sectorsPerAllocationUnit, bytesPerSector = bin.unpack("<LLII", response.data)

  status, err      = smb.stop(smbstate)

  return true, {
    TotalSize = totalAllocationUnits * sectorsPerAllocationUnit * bytesPerSector,
    FreeSize = totalFreeAllocationUnits * sectorsPerAllocationUnit * bytesPerSector
  }
end

-- Taken from smb lib

function send_transaction2(smbstate, sub_command, function_parameters, function_data, overrides)
  overrides = overrides or {}
  local header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, pid, mid
  local header, parameters, data
  local parameter_offset = 0
  local parameter_size   = 0
  local data_offset      = 0
  local data_size        = 0
  local total_word_count, total_data_count, reserved1, parameter_count, parameter_displacement, data_count, data_displacement, setup_count, reserved2
  local response = {}

  -- Header is 0x20 bytes long (not counting NetBIOS header).
  header = smb.smb_encode_header(smbstate, smb.command_codes['SMB_COM_TRANSACTION2'], overrides) -- 0x32 = SMB_COM_TRANSACTION2

  if(function_parameters) then
    parameter_offset = 0x44
    parameter_size = #function_parameters
    data_offset = #function_parameters + 33 + 32
  end

  -- Parameters are 0x20 bytes long.
  parameters = bin.pack("<SSSSCCSISSSSSCCS",
    parameter_size,                  -- Total parameter count.
    data_size,                       -- Total data count.
    0x000a,                          -- Max parameter count.
    0x3984,                          -- Max data count.
    0x00,                            -- Max setup count.
    0x00,                            -- Reserved.
    0x0000,                          -- Flags (0x0000 = 2-way transaction, don't disconnect TIDs).
    0x00001388,                      -- Timeout (0x00000000 = return immediately).
    0x0000,                          -- Reserved.
    parameter_size,                  -- Parameter bytes.
    parameter_offset,                -- Parameter offset.
    data_size,                       -- Data bytes.
    data_offset,                     -- Data offset.
    0x01,                            -- Setup Count
    0x00,                            -- Reserved
    sub_command                      -- Sub command
    )

  local data = "\0\0\0" .. (function_parameters or '')
  .. (function_data or '')

  -- Send the transaction request
  stdnse.debug2("SMB: Sending SMB_COM_TRANSACTION2")
  local result, err = smb.smb_send(smbstate, header, parameters, data, overrides)
  if(result == false) then
    stdnse.debug1("SMB: Try SMBv2 connexion")
    local result, err = smb2.smb2_send(smbstate, header, parameters, data, overrides)
    if(result == false) then
      return false, err
    end
  end

  return true
end

function receive_transaction2(smbstate)

  -- Read the result
  local status, header, parameters, data = smb.smb_read(smbstate)
  if(status ~= true) then
    stdnse.debug1("SMB: Try SMBv2 connexion")
    local status, header, parameters, data = smb2.smb2_read(smbstate)
      if(status ~= true) then
        return false, header
      end
  end

  -- Check if it worked
  local pos, header1, header2, header3, header4, command, status, flags, flags2, pid_high, signature, unused, tid, pid, uid, mid = bin.unpack("<CCCCCICSSlSSSSS", header)
  if(header1 == nil or mid == nil) then
    return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [29]"
  end
  if(status ~= 0) then
    if(smb.status_names[status] == nil) then
      return false, string.format("Unknown SMB error: 0x%08x\n", status)
    else
      return false, smb.status_names[status]
    end
  end

  -- Parse the parameters
  local pos, total_word_count, total_data_count, reserved1, parameter_count, parameter_offset, parameter_displacement, data_count, data_offset, data_displacement, setup_count, reserved2 = bin.unpack("<SSSSSSSSSCC", parameters)
  if(total_word_count == nil or reserved2 == nil) then
    return false, "SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [30]"
  end

  -- Convert the parameter/data offsets into something more useful (the offset into the data section)
  -- - 0x20 for the header, - 0x01 for the length.
  parameter_offset = parameter_offset - 0x20 - 0x01 - #parameters - 0x02;
  -- - 0x20 for the header, - 0x01 for parameter length, the parameter length, and - 0x02 for the data length.
  data_offset = data_offset - 0x20 - 0x01 - #parameters - 0x02;

  -- I'm not sure I entirely understand why the '+1' is here, but I think it has to do with the string starting at '1' and not '0'.
  local function_parameters = string.sub(data, parameter_offset + 1, parameter_offset + parameter_count)
  local function_data       = string.sub(data, data_offset      + 1, data_offset      + data_count)

  local response = {}
  response['parameters'] = function_parameters
  response['data']       = function_data

  return true, response
end