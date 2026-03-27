Demo sample files for the secure deduplication notebook and API demo.

Files:
- exact_duplicate_a.txt
- exact_duplicate_b.txt
- partial_similar_a.txt
- partial_similar_b.txt

Recommended usage:

1. Exact duplicate PoW demo:
   upload exact_duplicate_a.txt first
   upload exact_duplicate_b.txt second
   expected result:
   duplicate detection plus PoW challenge plus successful duplicate reuse after proof

2. Partial similarity demo:
   upload partial_similar_a.txt
   upload partial_similar_b.txt
   expected result:
   visible shared chunks between the two files in /demo/compare-files

Suggested notebook paths:

path_a = REPO_ROOT / "demo_samples" / "partial_similar_a.txt"
path_b = REPO_ROOT / "demo_samples" / "partial_similar_b.txt"

or for the exact duplicate demo:

path_a = REPO_ROOT / "demo_samples" / "exact_duplicate_a.txt"
path_b = REPO_ROOT / "demo_samples" / "exact_duplicate_b.txt"