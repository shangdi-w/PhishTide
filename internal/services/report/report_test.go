package report

import (
	"strings"
	"testing"

	"phishsim/internal/core/store"
)

func TestBuildScoresAndAggregatesDepartments(t *testing.T) {
	camp := store.Campaign{ID: 7, Name: "Q4 <演练>"}
	results := []store.Result{
		{Email: "a@example.com", Department: "研发部", Sent: true, Opened: true, Clicked: true, Submitted: true},
		{Email: "b@example.com", Department: "研发部", Sent: true, Opened: true},
		{Email: "c@example.com", Department: "财务部", Sent: true, Opened: true, Clicked: true, Reported: true},
		{Email: "d@example.com", Department: "", Sent: true},
	}
	rep := Build(camp, results)
	if rep.Totals.Users != 4 || rep.Totals.HighRisk != 1 {
		t.Fatalf("totals = %+v", rep.Totals)
	}
	if rep.Users[0].Email != "a@example.com" || rep.Users[0].Score != 100 {
		t.Fatalf("top risk = %+v", rep.Users[0])
	}
	if rep.Users[1].Email != "c@example.com" || rep.Users[1].Score != 20 {
		t.Fatalf("second risk = %+v", rep.Users[1])
	}
	if len(rep.Departments) != 3 {
		t.Fatalf("departments = %+v", rep.Departments)
	}
	if rep.Departments[0].Department != "研发部" || rep.Departments[0].AvgScore != 55 {
		t.Fatalf("top department = %+v", rep.Departments[0])
	}
	if rep.Departments[2].Department != "未分组" {
		t.Fatalf("empty department should be bucketed: %+v", rep.Departments)
	}

	html := rep.HTML()
	if !strings.Contains(html, "Q4 &lt;演练&gt;") {
		t.Fatal("campaign name is not HTML-escaped")
	}
	if !strings.Contains(html, "a@example.com") || !strings.Contains(html, "研发部") {
		t.Fatal("report body misses recipients/departments")
	}
}

func TestBuildVariantStats(t *testing.T) {
	camp := store.Campaign{ID: 9, Name: "AB", EmailTemplateBID: 3, ABSplit: 50}
	results := []store.Result{
		{Email: "a1@example.com", Sent: true, Opened: true, Clicked: true, Variant: "A"},
		{Email: "a2@example.com", Sent: true, Variant: "A"},
		{Email: "b1@example.com", Sent: true, Opened: true, Submitted: true, Variant: "B"},
		{Email: "b2@example.com", Sent: true, Opened: true, Reported: true, Variant: "B"},
		{Email: "m@example.com", Sent: true}, // empty variant defaults to A
	}
	rep := Build(camp, results)
	if len(rep.Variants) != 2 {
		t.Fatalf("variants = %+v", rep.Variants)
	}
	a, b := rep.Variants[0], rep.Variants[1]
	if a.Variant != "A" || b.Variant != "B" {
		t.Fatalf("variant order = %+v", rep.Variants)
	}
	if a.Users != 3 || a.Sent != 3 || a.Opened != 1 || a.Clicked != 1 || a.OpenRate < 33.2 || a.OpenRate > 33.4 {
		t.Fatalf("A stats = %+v", a)
	}
	if b.Users != 2 || b.Submitted != 1 || b.SubmitRate != 50 || b.Reported != 1 {
		t.Fatalf("B stats = %+v", b)
	}
	for _, u := range rep.Users {
		if u.Email == "m@example.com" && u.Variant != "A" {
			t.Fatalf("empty variant not defaulted: %+v", u)
		}
	}
	html := rep.HTML()
	if !strings.Contains(html, "A/B 模板对比") || !strings.Contains(html, "<th>分组</th>") {
		t.Fatal("variant section missing from report HTML")
	}
}

func TestScoreClampsAndReportLowers(t *testing.T) {
	if got := Score(store.Result{Reported: true}); got != 0 {
		t.Fatalf("reported-only score = %d, want 0", got)
	}
	if got := Score(store.Result{Opened: true, Clicked: true, Submitted: true}); got != 100 {
		t.Fatalf("max score = %d, want 100", got)
	}
	if Level(70) != "高" || Level(31) != "中" || Level(10) != "低" || Level(0) != "无" {
		t.Fatal("level thresholds changed")
	}
}
