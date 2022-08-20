#!/bin/bash

# Hack to ensure that if we are running on OS X with a homebrew installed
# GNU sed then we can still run sed.
runsed() {
  if hash gsed 2>/dev/null; then
    gsed "$@"
  else
    sed "$@"
  fi
}

git clone git@github.com:open-traffic-generator/models-yang
generator -path=models-yang -output_file=schema.go \
  -package_name=otgyang -generate_fakeroot -fakeroot_name=device -compress_paths=true \
  -shorten_enum_leaf_names \
  -trim_enum_openconfig_prefix \
  -typedef_enum_with_defmod \
  -enum_suffix_for_simple_union_enums \
  -exclude_modules=ietf-interfaces \
  -generate_rename \
  -generate_append \
  -generate_getters \
  -generate_leaf_getters \
  -generate_populate_defaults \
  -generate_simple_unions \
  -annotations \
  models-yang/models/interface/open-traffic-generator-port.yang \
  models-yang/models/flow/open-traffic-generator-flow.yang \
  models-yang/models/discovery/open-traffic-generator-discovery-interfaces.yang \
  models-yang/models/discovery/open-traffic-generator-discovery.yang

rm -rf models-yang
gofmt -w -s schema.go
