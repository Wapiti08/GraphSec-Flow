"""
Fill top_predicted_nodes in manual_labels CSV by running RootCauseAnalyzer
on each CVE. Returns ranked node IDs only — human annotators judge correctness.

Usage:
    python eval_root_ana.py --labels data/validation/manual_labels_1.csv --k 15
"""

import sys, csv, pickle, argparse, time
from pathlib import Path

sys.path.insert(0, Path(sys.path[0]).parent.as_posix())

from src.root_ana import RootCauseAnalyzer
from search.vamana import VamanaOnCVE, VamanaSearch
from cve.cvevector import CVEVector
from cent.temp_cent import TempCentricity
from cve.cveinfo import osv_cve_api
from cve.cvescore import load_cve_seve_json, cve_score_dict_gen, _normalize_cve_id, node_cve_score_agg


def build_analyzer(data_dir: Path):
    """Reconstruct the full analyzer pipeline (mirrors root_ana.main)."""
    depgraph      = pickle.loads((data_dir / "dep_graph_cve.pkl").read_bytes())
    per_cve       = pickle.loads((data_dir / "per_cve_scores.pkl").read_bytes())
    node_cve      = pickle.loads((data_dir / "node_cve_scores.pkl").read_bytes())
    node_texts    = pickle.loads((data_dir / "nodeid_to_texts.pkl").read_bytes())
    cve_meta_path = data_dir / "cve_records_for_meta.pkl"
    cve_records   = pickle.loads(cve_meta_path.read_bytes()) if cve_meta_path.exists() else None

    timestamps = {n: float(depgraph.nodes[n]["timestamp"]) for n in depgraph.nodes}

    embedder = CVEVector()
    vamana = VamanaOnCVE(depgraph, node_texts, embedder, VamanaSearch())
    vamana.build(cve_records=cve_records)

    analyzer = RootCauseAnalyzer(
        vamana=vamana,
        node_cve_scores=node_cve,
        timestamps=timestamps,
        centrality=TempCentricity(depgraph, "auto"),
    )

    cve_lookup = lambda cve_id: per_cve.get(cve_id, 0.0)
    return analyzer, embedder, timestamps, cve_lookup


def main(labels_path, output_path, data_dir="data", k=15, top_n=3):
    data_dir = Path(data_dir)
    analyzer, embedder, timestamps, cve_lookup = build_analyzer(data_dir)

    # Auto time window (IQR of all timestamps)
    all_ts = sorted(timestamps.values())
    t_s, t_e = all_ts[len(all_ts)//4], all_ts[3*len(all_ts)//4]

    # Read CSV
    with open(labels_path, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames)
        rows = list(reader)

    # Add timing column if not present
    if "prediction_time_ms" not in fieldnames:
        fieldnames.append("prediction_time_ms")

    print(f"Loaded {len(rows)} CVEs\n")

    # Track timing
    timings = []

    # For each CVE: run analyzer -> fill top_predicted_nodes + timing
    for i, row in enumerate(rows):
        cve_id = row["cve_id"]
        print(f"[{i+1}/{len(rows)}] {cve_id} ... ", end="", flush=True)

        try:
            # Encode CVE description
            cve_data = osv_cve_api(cve_id)
            data = cve_data.get("data", cve_data) if isinstance(cve_data, dict) else {}
            text = data.get("details") or data.get("summary") or ""
            query_vec = embedder.encode(text)

            # ---- Timed prediction ----
            t0 = time.perf_counter()

            result = analyzer.analyze(
                query_vector=query_vec,
                k=k, t_s=t_s, t_e=t_e,
                explain=True,
                cve_score_lookup=cve_lookup,
                return_diagnostics=True,
            )

            elapsed_ms = (time.perf_counter() - t0) * 1000
            # ------------------------------

            ranked = result[3] if len(result) == 4 else []
            top_ids = ranked[:top_n]
            row["top_predicted_nodes"] = "|".join(str(n) for n in top_ids)
            row["prediction_time_ms"] = f"{elapsed_ms:.1f}"
            timings.append(elapsed_ms)

            print(f"{row['top_predicted_nodes']}  ({elapsed_ms:.0f} ms)")

        except Exception as e:
            print(f"ERROR: {e}")
            row["top_predicted_nodes"] = ""
            row["prediction_time_ms"] = "error"

    # Write updated CSV
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    # ---- Timing summary ----
    if timings:
        timings_sorted = sorted(timings)
        n = len(timings)
        avg   = sum(timings) / n
        med   = timings_sorted[n // 2]
        p95   = timings_sorted[int(n * 0.95)]
        total = sum(timings)

        print(f"\n{'='*50}")
        print(f" TIMING SUMMARY ({n} predictions)")
        print(f"{'='*50}")
        print(f"  Total:   {total/1000:.2f} s")
        print(f"  Mean:    {avg:.1f} ms")
        print(f"  Median:  {med:.1f} ms")
        print(f"  Min:     {timings_sorted[0]:.1f} ms")
        print(f"  Max:     {timings_sorted[-1]:.1f} ms")
        print(f"  P95:     {p95:.1f} ms")
        print(f"{'='*50}")

    print(f"\nDone -> {out}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--labels", required=True)
    p.add_argument("--output", default="data/validation/manual_labels_predicted.csv")
    p.add_argument("--data_dir", default="data")
    p.add_argument("--k", type=int, default=15)
    p.add_argument("--top_n", type=int, default=3, help="Number of top node IDs to write")
    args = p.parse_args()
    main(args.labels, args.output, args.data_dir, args.k, args.top_n)