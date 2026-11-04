DetectorPackageInfo = { name = 'ips-web-bans', proto = 6,
    client = { init = 'DetectorInit', clean = 'DetectorClean', minimum_matches = 1 } }
function DetectorInit(detector)
    return detector
end
function DetectorClean() end
