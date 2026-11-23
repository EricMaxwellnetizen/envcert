"""Dataset integrity checks (EC080-EC084) for the dataset adapter.

These audit the data file itself -- the artifact RLVR/GRPO training and
most benchmark scoring actually consume:

- EC080 the answer must not be inside the agent-visible prompt;
- EC081 rows must not duplicate (exactly, by id, or near-duplicate prompts
  with conflicting labels);
- EC082 train/test-style splits must not share prompts (contamination);
- EC083 labels must not be degenerate (constant, empty, single-class);
- EC084 rows must parse and carry the fields the format promises.

Row caps keep pathological files bounded; caps are recorded as evidence.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter, defaultdict

from envcert.checks.base import CheckContext, CheckInfo, check, finding, not_applicable, passed
from envcert.core.models import Confidence, Severity, Status

MAX_ROWS_PER_FILE = 20000
MAX_PROMPTS_NEAR_DUP = 3000

PROMPT_FIELDS = ("prompt", "problem_statement", "question", "instruction", "input", "query", "task", "messages", "context", "text")
ANSWER_FIELDS = ("expected_answer", "answer", "target", "label", "expected_output", "expected", "output",
                 "gold_answer", "solution", "gold_patch", "patch", "completion", "response")
ID_FIELDS = ("instance_id", "task_id", "id", "uid", "uuid")
SPLIT_HINTS = ("train", "test", "eval", "dev", "valid", "validation", "holdout", "benchmark")

EC080 = CheckInfo("EC080", "Dataset answers are not embedded in agent-visible prompts", "dataset", Severity.HIGH,
                  "An expected answer that also appears verbatim in the prompt is leaked ground truth: the agent can copy it instead of solving the task.",
                  "Remove the answer from the prompt/input fields; keep ground truth in verifier-owned fields only.",
                  "Verbatim/normalised containment only; paraphrased leakage needs semantic review. Very short answers use exact-match to avoid flagging option lists.")
EC081 = CheckInfo("EC081", "Dataset has no duplicate or near-duplicate rows", "dataset", Severity.MEDIUM,
                  "Exact duplicates, reused ids and near-identical prompts (especially with conflicting labels) inflate scores, leak across splits and corrupt training signal.",
                  "Deduplicate prompts, make ids unique, and resolve label conflicts by re-adjudicating the row.",
                  "Near-duplicates use word 5-gram Jaccard >= 0.9 over a bounded prompt sample; semantic duplicates need embedding review.")
EC082 = CheckInfo("EC082", "Dataset splits do not share prompts (no train/test overlap)", "dataset", Severity.HIGH,
                  "The same prompt in a train split and a test/eval split is contamination: test performance partly measures memorisation.",
                  "Remove overlapping prompts from one split (conventionally from train) and re-issue the dataset version.",
                  "Split membership is inferred from file names containing train/test/eval/dev/valid; unlabelled files return NOT_APPLICABLE.")
EC083 = CheckInfo("EC083", "Dataset labels are not degenerate", "dataset", Severity.MEDIUM,
                  "Constant, empty or single-class-dominated labels make any score meaningless and teach RLVR verifiers to accept anything.",
                  "Fix labelling, drop empty-label rows, and rebalance or document intentional skew.",
                  "Applies to the detected answer/label field; free-form generation datasets without labels return NOT_APPLICABLE.")
EC084 = CheckInfo("EC084", "Dataset rows parse and carry their promised fields", "dataset", Severity.HIGH,
                  "Unparseable lines, missing prompts and missing labels silently shrink or corrupt the evaluated population.",
                  "Repair or drop broken rows; keep prompt and label fields present on every row.",
                  "Bounded to the first rows per file (cap recorded in evidence); field names are detected from common conventions.")
AUX_VISIBLE_FIELDS = ("hints_text", "context", "passage", "document", "instructions", "hint")
EC085 = CheckInfo("EC085", "Dataset grading specifications are consistent (FAIL_TO_PASS/PASS_TO_PASS style)", "dataset", Severity.HIGH,
                  "Test-graded instances grade by running named tests: an empty must-pass set grades nothing, and a test listed as both must-pass-after and must-pass-before makes the instance ungradeable.",
                  "Give every instance a non-empty FAIL_TO_PASS set disjoint from PASS_TO_PASS; regenerate the instance if its test patch changed.",
                  "Applies to SWE-bench-style rows carrying FAIL_TO_PASS/PASS_TO_PASS fields (JSON-encoded lists); other datasets return NOT_APPLICABLE.")


def _text_of(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, dict):
                parts.append(str(item.get("content") or item.get("text") or json.dumps(item, sort_keys=True)))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    return json.dumps(value, sort_keys=True)


def _first_field(row: dict, fields: tuple[str, ...]) -> str | None:
    for f in fields:
        if f in row and row[f] not in (None, ""):
            return f
    return None


def load_dataset_rows(ctx) -> dict:
    """Return {files: {rel: {rows, parse_errors, total_lines}}, prompt_field, answer_field}."""
    cached = getattr(ctx, "_dataset_cache", None)
    if cached is not None:
        result_cached: dict = cached
        return result_cached
    files: dict[str, dict] = {}
    prompt_votes: Counter = Counter()
    answer_votes: Counter = Counter()
    for rel in ctx.dataset_files:
        rows: list[dict] = []
        parse_errors = 0
        total = 0
        if rel.lower().endswith(".parquet"):
            # Parquet is binary; the stdlib cannot read it.  Use pyarrow when
            # the user has it, otherwise report the file as uninspectable
            # rather than pretending it was audited.
            try:
                import pyarrow.parquet as pq  # type: ignore

                table = pq.read_table(ctx.root / rel)
                total = table.num_rows
                rows = table.slice(0, MAX_ROWS_PER_FILE).to_pylist()
            except ImportError:
                parse_errors += 1
                ctx.warnings.append(f"dataset file {rel}: parquet support requires pyarrow (pip install pyarrow); rows were not inspected")
            except Exception:  # noqa: BLE001 - a corrupt parquet must not crash the audit
                parse_errors += 1
            files[rel] = {"rows": rows, "parse_errors": parse_errors, "total_lines": total}
            continue
        # Stream from disk: dataset files routinely exceed the 2MB
        # read_text_safe cap used for bundle text, and a truncated read
        # would silently audit only the head of the file.
        path = ctx.root / rel
        try:
            file_size = path.stat().st_size
        except OSError:
            file_size = 0
        parsed_array = False
        if rel.lower().endswith(".json") and file_size <= 25_000_000:
            raw = ctx.text(rel)
            if raw is not None and raw.lstrip().startswith("["):
                try:
                    obj = json.loads(raw)
                    items = obj if isinstance(obj, list) else []
                    total = len(items)
                    rows = [r for r in items[:MAX_ROWS_PER_FILE] if isinstance(r, dict)]
                    parse_errors = len(items) - len([r for r in items if isinstance(r, dict)])
                    parsed_array = True
                except ValueError:
                    parse_errors += 1
        if file_size > 25_000_000 and rel.lower().endswith(".json"):
            ctx.warnings.append(f"dataset file {rel}: single-document JSON over 25MB is not streamable; convert to JSONL for a full audit")
            parse_errors += 1
            files[rel] = {"rows": rows, "parse_errors": parse_errors, "total_lines": total}
            continue
        try:
            fh = None if parsed_array else path.open("r", encoding="utf-8", errors="replace", newline="")
        except OSError:
            fh = None
        if fh is not None:
            with fh:
                if rel.lower().endswith(".csv"):
                    try:
                        for row in csv.DictReader(fh):
                            total += 1
                            if total <= MAX_ROWS_PER_FILE:
                                rows.append(dict(row))
                    except csv.Error:
                        parse_errors += 1
                else:  # JSONL: one object per line, streamed
                    for line in fh:
                        if not line.strip():
                            continue
                        total += 1
                        try:
                            obj = json.loads(line)
                        except ValueError:
                            parse_errors += 1
                            continue
                        if isinstance(obj, dict):
                            if total <= MAX_ROWS_PER_FILE:
                                rows.append(obj)
                        else:
                            parse_errors += 1
        for row in rows[:500]:
            pf = _first_field(row, PROMPT_FIELDS)
            af = _first_field(row, ANSWER_FIELDS)
            if pf:
                prompt_votes[pf] += 1
            if af:
                answer_votes[af] += 1
        files[rel] = {"rows": rows, "parse_errors": parse_errors, "total_lines": total}
    result: dict = {
        "files": files,
        "prompt_field": prompt_votes.most_common(1)[0][0] if prompt_votes else None,
        "answer_field": answer_votes.most_common(1)[0][0] if answer_votes else None,
    }
    ctx._dataset_cache = result  # type: ignore[attr-defined]
    return result


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


def _prompt_hash(prompt: str) -> str:
    return hashlib.sha256(_norm(prompt).encode()).hexdigest()


def _all_rows(data: dict):
    for rel, info in data["files"].items():
        for idx, row in enumerate(info["rows"]):
            yield rel, idx, row


def _prompt_of(row: dict, field: str | None) -> str:
    return _text_of(row.get(field)) if field else ""


def _answer_of(row: dict, field: str | None) -> str:
    return _text_of(row.get(field)) if field else ""


@check(EC080)
def check_answer_in_prompt(c: CheckContext) -> list:
    ctx = c.task
    if ctx.adapter != "dataset":
        return [not_applicable(EC080, "Dataset leakage checks require the dataset adapter (a .jsonl/.json/.csv file).")]
    data = load_dataset_rows(ctx)
    pf, af = data["prompt_field"], data["answer_field"]
    if not pf or not af:
        return [not_applicable(EC080, f"Could not detect both prompt and answer fields (prompt={pf!r}, answer={af!r}); leakage cannot be assessed.")]
    leaks = []
    checked = 0
    for rel, idx, row in _all_rows(data):
        prompt, answer = _prompt_of(row, pf), _answer_of(row, af)
        # Auxiliary agent-visible fields (SWE-bench hints_text, RAG context,
        # passages) can carry the same leak as the prompt itself.
        aux = "\n".join(_text_of(row.get(f)) for f in AUX_VISIBLE_FIELDS if row.get(f))
        if aux:
            prompt = prompt + "\n" + aux
        if not prompt or not answer:
            continue
        checked += 1
        norm_answer = _norm(answer)
        norm_prompt = _norm(prompt)
        if len(norm_answer) >= 8:
            leaked = norm_answer in norm_prompt
        else:
            # Short answers appear in legitimate option lists; only flag
            # explicit disclosure phrasing or a prompt that is just the answer.
            leaked = norm_answer == norm_prompt or f"answer is {norm_answer}" in norm_prompt \
                or f"answer: {norm_answer}" in norm_prompt or f"expected answer is {norm_answer}" in norm_prompt
        if leaked:
            leaks.append({"file": rel, "row": idx, "id": _text_of(row.get(_first_field(row, ID_FIELDS) or ""))[:40]})
    ev = {"checked_rows": checked, "leak_count": len(leaks), "examples": leaks[:10], "prompt_field": pf, "answer_field": af}
    if leaks:
        return [finding(EC080, Status.WARN,
                        f"{len(leaks)}/{checked} rows embed the expected answer verbatim in the agent-visible prompt field '{pf}'; those rows grade copying, not solving.",
                        severity=Severity.HIGH, evidence=ev, confidence=Confidence.HIGH)]
    return [passed(EC080, f"No expected answers found verbatim in prompts across {checked} rows.", evidence=ev)]


def _shingles(text: str, n: int = 5) -> set[str]:
    words = _norm(text).split()
    if len(words) < n:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i:i + n]) for i in range(len(words) - n + 1)}


@check(EC081)
def check_duplicates(c: CheckContext) -> list:
    ctx = c.task
    if ctx.adapter != "dataset":
        return [not_applicable(EC081, "Dataset duplicate checks require the dataset adapter.")]
    data = load_dataset_rows(ctx)
    pf, af = data["prompt_field"], data["answer_field"]
    if not pf:
        return [not_applicable(EC081, "No prompt field detected; duplicates cannot be assessed.")]
    by_hash: dict[str, list] = defaultdict(list)
    by_id: Counter = Counter()
    prompts: list[str] = []
    for rel, idx, row in _all_rows(data):
        prompt = _prompt_of(row, pf)
        if not prompt:
            continue
        prompts.append(prompt)
        by_hash[_prompt_hash(prompt)].append((rel, idx, _answer_of(row, af)))
        id_field = _first_field(row, ID_FIELDS)
        if id_field:
            by_id[_text_of(row.get(id_field))] += 1
    exact_dup_rows = sum(len(v) - 1 for v in by_hash.values() if len(v) > 1)
    conflicts = [h for h, v in by_hash.items() if len({a for *_x, a in v}) > 1]
    dup_ids = {k: n for k, n in by_id.items() if n > 1 and k}
    # near-duplicates via shingle inverted index over a bounded sample
    sample = prompts[:MAX_PROMPTS_NEAR_DUP]
    shingle_sets = [_shingles(p) for p in sample]
    index: dict[str, list[int]] = defaultdict(list)
    for i, sh in enumerate(shingle_sets):
        for s in list(sh)[:40]:
            index[s].append(i)
    near_pairs = 0
    seen_pairs: set[tuple[int, int]] = set()
    for rows_with in index.values():
        if len(rows_with) > 20:
            continue
        for a in range(len(rows_with)):
            for b in range(a + 1, len(rows_with)):
                pair = (rows_with[a], rows_with[b])
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                sa, sb = shingle_sets[pair[0]], shingle_sets[pair[1]]
                if sa and sb and len(sa & sb) / len(sa | sb) >= 0.9:
                    near_pairs += 1
    ev = {"rows": len(prompts), "exact_duplicate_rows": exact_dup_rows, "conflicting_label_groups": len(conflicts),
          "duplicate_ids": len(dup_ids), "near_duplicate_pairs_sampled": near_pairs,
          "near_dup_sample_cap": MAX_PROMPTS_NEAR_DUP}
    problems = []
    if exact_dup_rows:
        problems.append(f"{exact_dup_rows} exact duplicate prompt row(s)")
    if conflicts:
        problems.append(f"{len(conflicts)} prompt group(s) carry conflicting labels")
    if dup_ids:
        problems.append(f"{len(dup_ids)} reused id value(s)")
    if near_pairs:
        problems.append(f"{near_pairs} near-duplicate prompt pair(s) (Jaccard >= 0.9, sampled)")
    if problems:
        return [finding(EC081, Status.WARN, "Dataset duplication: " + "; ".join(problems) + ". Duplicates inflate measured performance and can carry answers across splits.",
                        severity=Severity.HIGH if conflicts else Severity.MEDIUM, evidence=ev, confidence=Confidence.HIGH)]
    return [passed(EC081, f"No exact/near duplicates, id reuse or label conflicts across {len(prompts)} rows.", evidence=ev)]


@check(EC082)
def check_split_overlap(c: CheckContext) -> list:
    ctx = c.task
    if ctx.adapter != "dataset":
        return [not_applicable(EC082, "Dataset split checks require the dataset adapter.")]
    data = load_dataset_rows(ctx)
    pf = data["prompt_field"]
    if not pf:
        return [not_applicable(EC082, "No prompt field detected; split overlap cannot be assessed.")]
    groups: dict[str, set[str]] = defaultdict(set)
    for rel, info in data["files"].items():
        name = rel.rsplit("/", 1)[-1].lower()
        split = next((h for h in SPLIT_HINTS if h in name), None)
        if split is None:
            continue
        for row in info["rows"]:
            prompt = _prompt_of(row, pf)
            if prompt:
                groups[split].add(_prompt_hash(prompt))
    if len(groups) < 2:
        return [not_applicable(EC082, "Fewer than two split-labelled dataset files (train/test/eval/dev in file names); overlap cannot be assessed.")]
    overlaps: list[dict] = []
    keys = sorted(groups)
    for i, a in enumerate(keys):
        for b in keys[i + 1:]:
            shared = groups[a] & groups[b]
            if shared:
                overlaps.append({"splits": [a, b], "shared_prompts": len(shared)})
    ev = {"splits": {k: len(v) for k, v in groups.items()}, "overlaps": overlaps}
    if overlaps:
        total = sum(o["shared_prompts"] for o in overlaps)
        return [finding(EC082, Status.WARN,
                        f"{total} prompt(s) appear in more than one split ({'; '.join(o['splits'][0] + '/' + o['splits'][1] + ': ' + str(o['shared_prompts']) for o in overlaps)}); test rows present in training data are contamination.",
                        severity=Severity.HIGH, evidence=ev, confidence=Confidence.HIGH)]
    return [passed(EC082, "No prompt is shared between the detected splits.", evidence=ev)]


@check(EC083)
def check_degenerate_labels(c: CheckContext) -> list:
    ctx = c.task
    if ctx.adapter != "dataset":
        return [not_applicable(EC083, "Dataset label checks require the dataset adapter.")]
    data = load_dataset_rows(ctx)
    af = data["answer_field"]
    if not af:
        return [not_applicable(EC083, "No answer/label field detected; degeneracy cannot be assessed (free-form datasets may legitimately have none).")]
    answers: list[str] = []
    missing = 0
    total = 0
    for _rel, _idx, row in _all_rows(data):
        total += 1
        value = _answer_of(row, af)
        if not value.strip():
            missing += 1
        else:
            answers.append(_norm(value))
    counts = Counter(answers)
    ev = {"answer_field": af, "rows": total, "missing_or_empty": missing,
          "unique_labels": len(counts), "top_label_share": (counts.most_common(1)[0][1] / len(answers)) if answers else 0}
    problems = []
    if missing:
        problems.append(f"{missing}/{total} rows have an empty '{af}'")
    if answers and len(counts) == 1 and total >= 5:
        problems.append(f"every label is identical ('{counts.most_common(1)[0][0][:40]}')")
    elif answers and ev["top_label_share"] >= 0.98 and len(answers) >= 20:
        problems.append(f"one label accounts for {ev['top_label_share']:.0%} of rows")
    if problems:
        return [finding(EC083, Status.WARN, "Degenerate labels: " + "; ".join(problems) + "; scores on this data cannot distinguish good from bad outputs.",
                        severity=Severity.MEDIUM, evidence=ev, confidence=Confidence.HIGH)]
    return [passed(EC083, f"Labels are present and non-degenerate ({len(counts)} unique value(s), top share {ev['top_label_share']:.0%}).", evidence=ev)]


def _name_list(value) -> list[str] | None:
    """Parse a FAIL_TO_PASS-style field: JSON list string, list, or None."""
    if value is None or value == "":
        return None
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return [value]
        return [str(v) for v in parsed] if isinstance(parsed, list) else [value]
    return [str(value)]


@check(EC085)
def check_grading_spec(c: CheckContext) -> list:
    ctx = c.task
    if ctx.adapter != "dataset":
        return [not_applicable(EC085, "Dataset grading-spec checks require the dataset adapter.")]
    data = load_dataset_rows(ctx)
    checked = 0
    empty_fail: list[dict] = []
    overlaps: list[dict] = []
    for rel, idx, row in _all_rows(data):
        fail_to_pass = _name_list(row.get("FAIL_TO_PASS"))
        if fail_to_pass is None and "FAIL_TO_PASS" not in row:
            continue
        checked += 1
        row_id = _text_of(row.get(_first_field(row, ID_FIELDS) or ""))[:60]
        if not fail_to_pass:
            empty_fail.append({"file": rel, "row": idx, "id": row_id})
            continue
        pass_to_pass = _name_list(row.get("PASS_TO_PASS")) or []
        shared = sorted(set(fail_to_pass) & set(pass_to_pass))
        if shared:
            overlaps.append({"file": rel, "row": idx, "id": row_id, "shared_tests": shared[:5]})
    if checked == 0:
        return [not_applicable(EC085, "No FAIL_TO_PASS-style grading fields found; this check applies to test-graded (SWE-bench-style) datasets.")]
    ev = {"instances_checked": checked, "empty_fail_to_pass": empty_fail[:10], "overlapping_specs": overlaps[:10]}
    problems = []
    if empty_fail:
        problems.append(f"{len(empty_fail)} instance(s) have an empty FAIL_TO_PASS set (nothing grades them)")
    if overlaps:
        problems.append(f"{len(overlaps)} instance(s) list the same test in FAIL_TO_PASS and PASS_TO_PASS (ungradeable)")
    if problems:
        return [finding(EC085, Status.WARN, "Grading-spec integrity: " + "; ".join(problems) + ".",
                        severity=Severity.HIGH, evidence=ev, confidence=Confidence.HIGH)]
    return [passed(EC085, f"All {checked} test-graded instances have non-empty, disjoint FAIL_TO_PASS/PASS_TO_PASS sets.", evidence=ev)]


@check(EC084)
def check_row_integrity(c: CheckContext) -> list:
    ctx = c.task
    if ctx.adapter != "dataset":
        return [not_applicable(EC084, "Dataset row checks require the dataset adapter.")]
    data = load_dataset_rows(ctx)
    pf, af = data["prompt_field"], data["answer_field"]
    parse_errors = sum(i["parse_errors"] for i in data["files"].values())
    total_lines = sum(i["total_lines"] for i in data["files"].values())
    missing_prompt = missing_answer = empty_prompt = 0
    rows_seen = 0
    for _rel, _idx, row in _all_rows(data):
        rows_seen += 1
        if pf and not _prompt_of(row, pf).strip():
            missing_prompt += 1
        elif pf and len(_prompt_of(row, pf).strip()) < 3:
            empty_prompt += 1
        if af and not _answer_of(row, af).strip():
            missing_answer += 1
    ev = {"files": {rel: {"rows": len(i["rows"]), "parse_errors": i["parse_errors"], "total_lines": i["total_lines"]}
                    for rel, i in data["files"].items()},
          "prompt_field": pf, "answer_field": af, "missing_prompt": missing_prompt,
          "trivial_prompt": empty_prompt, "missing_answer": missing_answer, "row_cap_per_file": MAX_ROWS_PER_FILE}
    problems = []
    if parse_errors:
        problems.append(f"{parse_errors} unparseable row(s)")
    if pf is None and rows_seen:
        problems.append("no recognisable prompt field on any row")
    if missing_prompt:
        problems.append(f"{missing_prompt} row(s) missing/empty prompt")
    if rows_seen and total_lines > rows_seen and parse_errors == 0:
        pass  # cap reached, not an integrity problem
    if problems:
        return [finding(EC084, Status.WARN, "Dataset integrity: " + "; ".join(problems) + f" ({rows_seen} rows inspected). Broken rows silently change what is being measured.",
                        severity=Severity.HIGH, evidence=ev, confidence=Confidence.HIGH)]
    return [passed(EC084, f"All {rows_seen} inspected rows parse and carry their prompt fields.", evidence=ev)]
