# models/

Each trained dataset gets its own subfolder here (e.g.
`models/cicids2017_combined_8_files/`), named from a slugified version
of the dataset name - `random_forest.pkl`, `xgboost.pkl`,
`isolation_forest.pkl`, `label_encoder.pkl`, `preprocessing.pkl` (the
fitted ColumnTransformer + feature schema), and `model_meta.json`
(metrics, feature schema, timestamps) all live inside that one
subfolder. This is what lets training a new/different dataset never
overwrite another dataset's already-trained model - see
`ml/train_model.py`'s module docstring.

`active_model.json` at this folder's root records which single slot
`load_models()` returns by default for the Threat Detection page's
Model Evaluation and "Run AI Detection" sections - switchable from the
UI without retraining anything.

This folder is empty until the first "Train Models" click, and every
subfolder's contents (plus `active_model.json`) are git-ignored
(they're generated artifacts, not source code).
