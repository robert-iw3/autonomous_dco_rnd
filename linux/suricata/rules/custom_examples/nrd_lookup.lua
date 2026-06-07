-- nrd_lookup.lua
function init(args)
    local needs = {}
    needs["http.host"] = tostring(true)
    return needs
end

function match(args)
    -- Example: List of NRDs (replace with integration to a threat intelligence feed)
    local nrd_list = {
        "example-malicious-domain.com",
        "newly-registered-c2.xyz"
        -- Add NRDs from your threat intelligence feed
    }
    local host = args["http.host"]
    if host then
        host = host:lower()
        for _, nrd in ipairs(nrd_list) do
            if host == nrd then
                return 1 -- Match found, trigger alert
            end
        end
    end
    return 0 -- No match
end