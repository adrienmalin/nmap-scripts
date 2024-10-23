local shortport = require "shortport"

description = [[
Return status, title and favicon URL of a webpage
]]

---
-- @args http-get.path Path to get. Default /.
--
-- @usage nmap -phttp,https --script http-info.nse --script-args http-info.path=/ <host>
--
-- @output
-- 80/tcp   open   http
-- | http-info: 
-- |   status-line: HTTP/1.1 200 OK\x0D
-- | 
-- |   title: Go ahead and ScanMe!
-- |   favicon: http://scanme.nmap.org:80/shared/images/tiny-eyeicon.png
-- |_  status: 200
---

categories = {"discovery", "intrusive"}
author     = "Adrien Malingrey"
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"

portrule = shortport.http

local http   = require "http"
local stdnse = require "stdnse"

action = function(host, port)
  local scheme = ""
  local hostaddress = (host.name ~= '' and host.name) or host.ip
  local path = "/"
  local favicon_relative_uri = "/favicon.ico"
  local favicon

  stdnse.debug1("port", port.service)
  if (port.service == "ssl") then
    scheme = "https"
  else
    scheme = port.service
  end
  stdnse.debug1("scheme", scheme)

  if(stdnse.get_script_args('http-get.path')) then
    path = stdnse.get_script_args('http-info.path')
  end

  stdnse.debug1("Try to download %s", path)
  local answer = http.get(hostaddress, port, path)

  local output = {status=answer.status, ["status-line"]=answer["status-line"]}

  if (answer and answer.status == 200) then
    stdnse.debug1("[SUCCESS] Load page %s", path)
    -- Taken from http-title.nse by Diman Todorov
    local title = string.match(answer.body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")
    if (title) then
      output.title = title
    end
    stdnse.debug1("[INFO] Try favicon %s", favicon_relative_uri)
    favicon_relative_uri = parseIcon(answer.body) or favicon_relative_uri
  else
    stdnse.debug1("[ERROR] Can't load page %s", path)
  end
  
  favicon = http.get(hostaddress, port, favicon_relative_uri)

  if (favicon and favicon.status == 200) then
    stdnse.debug1("[SUCCESS] Load favicon %s", favicon_relative_uri)
    output.favicon = favicon_relative_uri
  else
    stdnse.debug1("[ERROR] Can't load favicon %s", favicon_relative_uri)
  end
  
  return output
end

--- function taken from http_favicon.nse by Vlatko Kosturjak

function parseIcon( body )
  local _, i, j
  local rel, href, word

  -- Loop through link elements.
  i = 0
  while i do
    _, i = string.find(body, "<%s*[Ll][Ii][Nn][Kk]%s", i + 1)
    if not i then
      return nil
    end
    -- Loop through attributes.
    j = i
    while true do
      local name, quote, value
      _, j, name, quote, value = string.find(body, "^%s*(%w+)%s*=%s*([\"'])(.-)%2", j + 1)
      if not j then
        break
      end
      if string.lower(name) == "rel" then
        rel = value
      elseif string.lower(name) == "href" then
        href = value
      end
    end
    for word in string.gmatch(rel or "", "%S+") do
      if string.lower(word) == "icon" then
        return href
      end
    end
  end
end
