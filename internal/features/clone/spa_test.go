package clone

import "testing"

func TestAssetPathMapAndAPIReplayMap(t *testing.T) {
	assets := map[string]Asset{
		"https://sso.example.com/static/js/main.4f2a.js": {URL: "https://sso.example.com/static/js/main.4f2a.js", Path: "/__assets__/aa/main.4f2a.js"},
		"https://sso.example.com/api/user?id=7":          {URL: "https://sso.example.com/api/user?id=7", Path: "/__assets__/bb/user"},
		"https://sso.example.com/api/health":             {URL: "https://sso.example.com/api/health", Path: "/__assets__/cc/health"},
	}
	captured := []netResource{
		{URL: "https://sso.example.com/api/user?id=7", Mime: "application/json", API: true},
		// An API response that was not mirrored (over budget) must be skipped.
		{URL: "https://sso.example.com/api/missing", Mime: "application/json", API: true},
		// A non-API resource never reaches the replay map.
		{URL: "https://sso.example.com/static/js/main.4f2a.js", Mime: "application/javascript"},
	}

	wantAsset := map[string]string{
		"/static/js/main.4f2a.js": "/__assets__/aa/main.4f2a.js",
		"/api/user":               "/__assets__/bb/user",
		"/api/health":             "/__assets__/cc/health",
	}
	got := assetPathMap(assets)
	if len(got) != len(wantAsset) {
		t.Fatalf("assetPathMap = %v", got)
	}
	for k, v := range wantAsset {
		if got[k] != v {
			t.Errorf("assetPathMap[%q] = %q want %q", k, got[k], v)
		}
	}

	api := apiReplayMap(captured, assets)
	if len(api) != 1 {
		t.Fatalf("apiReplayMap = %v", api)
	}
	if api["/api/user?id=7"] != "/__assets__/bb/user" {
		t.Fatalf("api replay miss: %v", api)
	}
}
