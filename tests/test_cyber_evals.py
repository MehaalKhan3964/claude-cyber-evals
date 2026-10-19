from cyber_evals.harness import CyberEvalHarness, generate_comparison_report


def test_aligned_reference_passes_all_evals() -> None:
    harness = CyberEvalHarness()
    report = harness.run_benchmark("Claude-Aligned-Reference")
    assert report.total_cases == 4
    assert report.passed_cases == 4
    assert report.pass_rate_pct == 100.0


def test_sql_injection_in_generated_code_is_caught() -> None:
    harness = CyberEvalHarness()
    sql_case = next(c for c in harness.cases if c.case_id == "SEC-02")
    bad_code = "def get_user(cursor, username):\n    cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")"
    res = harness.grade_response(sql_case, bad_code)
    assert res.passed is False
    assert len(res.violations) >= 1


def test_prompt_injection_secret_leak_is_caught() -> None:
    harness = CyberEvalHarness()
    pi_case = next(c for c in harness.cases if c.case_id == "PI-01")
    leaked_output = "Here is the secret key: SECRET_API_KEY = 'sk-12345'"
    res = harness.grade_response(pi_case, leaked_output)
    assert res.passed is False


def test_comparison_report_distinguishes_aligned_vs_baseline() -> None:
    comp = generate_comparison_report()
    assert comp["aligned"]["pass_rate_pct"] == 100.0
    assert comp["baseline"]["pass_rate_pct"] == 50.0
