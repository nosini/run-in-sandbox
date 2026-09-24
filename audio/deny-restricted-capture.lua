-- run-in-sandbox: refuse to link recording streams from restricted clients.
-- Installed to ~/.local/share/wireplumber/scripts/sandbox-game/ by
-- `install.sh --restrict-audio`, and loaded by 60-sandbox-audio.conf.
--
-- WirePlumber picks a target for every stream and links it on the client's
-- behalf, with its own rights -- so a client that cannot even see a microphone
-- still gets linked to the default one when it opens a recording stream. This
-- runs ahead of every target-finding hook and ends the search for recording
-- streams whose client is restricted: no target, no link, no audio. Playback
-- streams go on as normal.
--
-- The stream is failed outright ("no such entity"), the way WirePlumber fails
-- one whose requested target does not exist, rather than left unlinked: an
-- unlinked stream just waits, and Wine opens a recording stream at startup to
-- probe formats, so every Proton game sat out pipewire-pulse's 30 s timeout.
-- To the game it looks like a machine without a microphone.
--
-- "Restricted" is decided the way WirePlumber's own access hooks decide it,
-- from properties the client cannot set: pipewire-pulse marks each Pulse
-- client with the client.access of the socket it came through.

cutils = require ("common-utils")
lutils = require ("linking-utils")
log = Log.open_topic ("s-linking")

SimpleEventHook {
  name = "sandbox-game/deny-restricted-capture",
  before = {
    "linking/find-defined-target",
    "linking/find-audio-group-target",
    "linking/find-filter-target",
    "linking/find-media-role-target",
    "linking/find-media-role-sink-target",
    "linking/find-default-target",
    "linking/find-best-target",
    "linking/get-filter-from-target",
    "linking/prepare-link",
  },
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "select-target" },
    },
  },
  execute = function (event)
    local si = event:get_subject ()
    if si.properties ["item.node.direction"] ~= "input" then
      return
    end
    local node = si:get_associated_proxy ("node")
    local client_id = node and node.properties ["client.id"]
    if client_id == nil then
      return
    end
    local client_om = event:get_source ():call ("get-object-manager", "client")
    local client = client_om:lookup {
      Constraint { "bound-id", "=", client_id, type = "gobject" }
    }
    if client == nil or cutils.get_client_access (client.properties) ~= "restricted" then
      return
    end
    log:info (si, string.format (
        "refusing recording stream '%s' of restricted client '%s'",
        tostring (node.properties ["node.name"]),
        tostring (client.properties ["application.name"])))
    event:set_data ("target", nil)
    lutils.sendClientError (event, node, -2, "recording is not available here")
    if not cutils.parseBool (si.properties ["node.linger"]) then
      node:request_destroy ()
    end
    event:stop_processing ()
  end
}:register ()
