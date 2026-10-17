# Lab contract

`lab/local.yaml` is the only place that names a machine. Copy `lab/contract.example.yaml` and fill it. The agent reads that file at the start of `skill/SKILL.md` and nowhere else for paths.

Required keys: `scope`, `product_log`, `install_dir`, `data_dir`, `session1_admin`, `restore`, `os`, `hvci`.

The product log is the oracle. Do not hardcode a log path into a card.
