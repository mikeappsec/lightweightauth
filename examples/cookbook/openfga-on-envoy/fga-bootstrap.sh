#!/bin/sh
# Bootstrap a local OpenFGA store with a tiny "documents" model and
# two demo tuples. Echoes RESULT_STORE / RESULT_MODEL on stdout so a
# wrapper script can capture them.
#
# Run inside a Pod that can resolve `openfga` in the namespace, e.g.
#   kubectl -n lwauth-demo run fga-init --image=curlimages/curl:8.10.1 \
#     --restart=Never --rm -i --command -- sh -c "$(cat fga-bootstrap.sh)"
set -eu
FGA="${FGA_URL:-http://openfga:8080}"

echo ">> create store"
STORE=$(curl -sfS -X POST "$FGA/stores" \
  -H 'content-type: application/json' \
  -d '{"name":"documents-demo"}' \
  | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
[ -n "$STORE" ] || { echo "no store id"; exit 1; }
echo "STORE=$STORE"

echo ">> write authorization model"
MODEL=$(curl -sfS -X POST "$FGA/stores/$STORE/authorization-models" \
  -H 'content-type: application/json' \
  --data-binary @- <<'JSON' \
  | sed -n 's/.*"authorization_model_id":"\([^"]*\)".*/\1/p'
{"schema_version":"1.1","type_definitions":[
  {"type":"user"},
  {"type":"document",
   "relations":{
     "viewer":{"this":{}},
     "editor":{"this":{}},
     "owner": {"this":{}}
   },
   "metadata":{"relations":{
     "viewer":{"directly_related_user_types":[{"type":"user"}]},
     "editor":{"directly_related_user_types":[{"type":"user"}]},
     "owner": {"directly_related_user_types":[{"type":"user"}]}
   }}}
]}
JSON
)
[ -n "$MODEL" ] || { echo "no model id"; exit 1; }
echo "MODEL=$MODEL"

echo ">> write tuples (alice:viewer, carol:owner on document:42)"
curl -sfS -X POST "$FGA/stores/$STORE/write" \
  -H 'content-type: application/json' \
  --data-binary @- <<JSON
{"writes":{"tuple_keys":[
  {"user":"user:alice","relation":"viewer","object":"document:42"},
  {"user":"user:carol","relation":"owner", "object":"document:42"}
]},"authorization_model_id":"$MODEL"}
JSON
echo

echo ">> sanity Check (alice viewer document:42 — expect allowed:true)"
curl -sfS -X POST "$FGA/stores/$STORE/check" \
  -H 'content-type: application/json' \
  -d "{\"tuple_key\":{\"user\":\"user:alice\",\"relation\":\"viewer\",\"object\":\"document:42\"},\"authorization_model_id\":\"$MODEL\"}"
echo

echo "RESULT_STORE=$STORE"
echo "RESULT_MODEL=$MODEL"
