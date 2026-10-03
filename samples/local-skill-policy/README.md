# Synthetic Local Skill policy example

These files document the JSON shape and support policy unit tests. All Skill names, instance aliases and table identifiers are invented, and hashes are placeholders. They are not an audited deployment and are never loaded automatically by Gateway.

Real policies belong outside the Gateway project, normally under `~/.config/mac-file-gateway/local-skill-policy/`, and are selected with `--local-skill-policy-dir`. Keep the two files together as a reviewed version. Every executable Skill must declare a supported `kind`. `agent_dir_env` is an explicit local integration setting, and cloud scripts use `command_script_sections` to select their audited argument sections.

For updates, the evidence collector creates a new draft directory, changes evidence hashes only and marks both JSON files `review_status: draft`. Manually audit the source/permission changes, mark both files approved, run the compatibility checker and restart Gateway. Do not replace production policy with these examples.
