# Convert the output of `terraform show -json <plan>` into the shape that
# Conftest's hcl2 parser produces for .tf files, so the same Rego policies
# can evaluate both: {"resource": {"<type>": {"<name>": [{...attributes}]}}}.
#
# Two differences between a plan and HCL are handled here:
#
# - Values only known after apply are missing from `after` (they are listed in
#   `after_unknown`). If the code configured the attribute (for example it
#   references another resource), the value is filled with a placeholder, so a
#   policy sees "a value is set". If the code never set it, the provider
#   computes it (for example the default service account email), and it stays
#   absent, exactly as in HCL. The `configuration` section of the plan says
#   which attributes the code set. Without it, every unknown value is filled.
#
# - Attributes that are not set appear as null or as empty collections. They
#   are dropped, which is what an absent attribute looks like in HCL.

def child($config; $key):
  if $config == "ANY" then "ANY" else ($config | try .[$key] catch null) end;

def unknown_fill($unknown; $config):
  . as $value
  | if $unknown == true then
      (if $config == null then $value else "(known after apply)" end)
    elif ($unknown | type) == "object" then
      reduce ($unknown | keys_unsorted[]) as $key ($value // {};
        .[$key] = (($value // {})[$key] | unknown_fill($unknown[$key]; child($config; $key))))
    elif ($unknown | type) == "array" then
      [range(0; ([(($value // []) | length), ($unknown | length)] | max)) as $i
        | (($value // [])[$i]) | unknown_fill($unknown[$i]; child($config; $i))]
    else $value end;

# Empty objects are kept as list elements: `access_config {}` must stay `[{}]`.
def clean:
  if type == "object" then
    with_entries(.value |= clean)
    | with_entries(select(.value != null and .value != [] and .value != {}))
  elif type == "array" then map(clean)
  else . end;

# Follow "module.a.module.b" through module_calls to that module's configuration.
def module_config($root; $address):
  if $address == null then $root
  else
    ($address | split(".")) as $parts
    | reduce [range(1; ($parts | length); 2) as $i | ($parts[$i] | sub("\\[.*$"; ""))][] as $name
        ($root; .module_calls[$name].module)
  end;

def resource_name:
  (if .module_address then .module_address + "." else "" end)
  + .name
  + (if .index != null then "[\(.index | tojson)]" else "" end);

. as $plan
| [ .resource_changes[]?
    | select(.mode == "managed" and .change.after != null)
    | . as $rc
    | ([ module_config($plan.configuration.root_module // {}; $rc.module_address)
         | .resources[]?
         | select(.type == $rc.type and .name == $rc.name)
         | (.expressions // {}) ] | first // "ANY") as $config
    | {
        type: $rc.type,
        name: ($rc | resource_name),
        body: ($rc.change.after | unknown_fill($rc.change.after_unknown // {}; $config) | clean)
      }
  ]
| reduce .[] as $r ({resource: {}}; .resource[$r.type][$r.name] = [$r.body])
