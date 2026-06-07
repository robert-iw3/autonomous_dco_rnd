# Adversarial Corpus Templates

Training corpus templates for the Sovereign MLOps adversarial detection model.
Each TTP directory mirrors `arcanaeum/offsec/ttps/` and contains:

- **`stage_<ttp>_behavioral.py`** -- standalone template version of the mlops staging script,
  with full inline documentation explaining *what each tool class teaches the model*
- **`manifest.md`** -- human-readable breakdown of detection philosophy, tool coverage,
  and admin/adversarial discriminators for every class in the script

## Adding a New TTP

1. Create `adversarial_corpus_templates/<N>_<TTP>/`
2. Write `MANIFEST.md` (see `1_Recon/MANIFEST.md` as the template)
3. Write `stage_<ttp>_behavioral.py` (see `1_Recon/` for the pattern)
4. Copy to `mlops/scripts/` and wire into `01_spool_datasets.py` + `Makefile`
