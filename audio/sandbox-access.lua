-- run-in-sandbox: what a sandboxed game may see of the sound server.
-- Installed to ~/.local/share/wireplumber/scripts/sandbox-game/ by
-- `install.sh --restrict-audio`, and loaded by 60-sandbox-audio.conf.
--
-- Nothing by default, then only what playing sound takes: the sinks, the
-- default-device metadata, the factories a stream is made with, and the
-- client's own objects. Every other application's streams and clients stay
-- out of sight -- their titles (browser tabs, videos), binaries and PIDs --
-- and so do sources, monitors, devices and the link factory.
--
-- The client's own objects need a callback, which rules in the config cannot
-- express; that is why this is a script. It claims sandbox-game clients
-- ahead of the config's access.rules, whose permission manager stays there
-- as a backstop.

cutils = require ("common-utils")
log = Log.open_topic ("s-client")

nodes_om = ObjectManager { Interest { type = "node" } }
nodes_om:activate ()

local function own (client, object)
  local id = tostring (client["bound-id"])
  return object["bound-id"] == client["bound-id"]
      or object.properties["client.id"] == id
end

-- Its streams' links too: a stream does not finish playing (drain) without
-- them. Not other applications' links, which would map out what is playing.
local function own_link (client, link)
  local node = nodes_om:lookup {
    Constraint { "bound-id", "=", link.properties["link.output.node"], type = "gobject" } }
  return node ~= nil and own (client, node)
end

pm = PermissionManager ()
pm:set_default_permissions (Perm.NONE)
pm:set_core_permissions (Perm.RX)
pm:add_rules_match (Json.Raw [[
  [
    {
      matches = [
        { media.class = "Audio/Sink" }
        { metadata.name = "default" }
        { factory.name = "adapter" }
        { factory.name = "client-node" }
      ]
      actions = { set-permissions = "rx" }
    }
  ]
]])
for _, kind in ipairs ({ "client", "node", "port" }) do
  pm:add_interest_match (function (_, client, object)
    return own (client, object) and Perm.RWX or Perm.NONE
  end, Interest { type = kind })
end
pm:add_interest_match (function (_, client, link)
  return own_link (client, link) and Perm.RX or Perm.NONE
end, Interest { type = "link" })
pm:activate (Features.ALL, function (_, e)
  if e then
    log:warning ("sandbox-game: permission manager failed: " .. tostring (e))
  end
end)

SimpleEventHook {
  name = "sandbox-game/sandbox-access",
  before = { "client/find-config-access", "client/find-default-access",
             "client/apply-access" },
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "select-access" },
    },
  },
  execute = function (event)
    local client = event:get_subject ()
    if cutils.get_client_access (client.properties) ~= "sandbox-game"
        or event:get_data ("permission-manager") ~= nil then
      return
    end
    event:set_data ("permission-manager", pm)
  end
}:register ()
