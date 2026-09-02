#!/usr/bin/env bash
# Attempt us007-sbx-output-live-0127, run 2 (after the model fix that the
# run-1 mask-index survivor forced). Every exit code below is read from the
# real java command; nothing is inferred from a wrapper.
cd /home/agent/tlc || exit 99
rm -rf mut out && mkdir -p out mut

echo "=== staged artifact digests (must equal the host bytes) ==="
sha256sum FrameModel.tla FrameModel.cfg CloseModel.tla CloseModel.cfg tla2tools.jar

echo "=== window start ==="
date -u +%Y-%m-%dT%H:%M:%SZ | tee out/window-start.txt

for MOD in FrameModel CloseModel; do
  echo "=================== SANY $MOD ==================="
  java -cp tla2tools.jar tla2sany.SANY "$MOD.tla" > "out/sany-$MOD.out" 2>&1
  echo "SANY_${MOD}_EXIT=$?"
  tail -6 "out/sany-$MOD.out"
  echo "=================== TLC $MOD ==================="
  java -cp tla2tools.jar tlc2.TLC -config "$MOD.cfg" "$MOD" > "out/tlc-$MOD.out" 2>&1
  echo "TLC_${MOD}_EXIT=$?"
  grep -E "Model checking completed|Error:|states generated|depth of the complete|Finished in" "out/tlc-$MOD.out"
done

# ---- seeded defects: one per checked family, exactly as declared ----------
mkdir -p mut/frame-liveness mut/close-liveness mut/frame-mask mut/frame-alloc \
         mut/frame-length-site mut/close-echo mut/close-onebyte

cp FrameModel.tla mut/frame-liveness/FrameModel.tla
sed 's/^SPECIFICATION FairSpec$/SPECIFICATION Spec/' FrameModel.cfg > mut/frame-liveness/FrameModel.cfg

cp CloseModel.tla mut/close-liveness/CloseModel.tla
sed 's/^SPECIFICATION FairSpec$/SPECIFICATION Spec/' CloseModel.cfg > mut/close-liveness/CloseModel.cfg

# defect.frame.mask-index-misalignment (MaskApply only; the reference stays)
awk '/^MaskApply\(payload, key\) ==$/{p=1} p&&/key\[1 \+ \(\(i - 1\) % 4\)\]/{sub(/key\[1 \+ \(\(i - 1\) % 4\)\]/,"key[1 + (i % 4)]"); p=0} {print}' \
  FrameModel.tla > mut/frame-mask/FrameModel.tla
cp FrameModel.cfg mut/frame-mask/FrameModel.cfg

# defect.frame.allocate-before-gate
sed "s/  \/\\\\ allocated' = 0/  \/\\\\ allocated' = LengthOctets(f.length)/" \
  FrameModel.tla > mut/frame-alloc/FrameModel.tla
cp FrameModel.cfg mut/frame-alloc/FrameModel.cfg

# defect.frame.late-length-gate
sed 's/  THEN Reject(1009, LengthSite(f))/  THEN Reject(1009, FrameOctets(f))/' \
  FrameModel.tla > mut/frame-length-site/FrameModel.tla
cp FrameModel.cfg mut/frame-length-site/FrameModel.cfg

# defect.close.echo-mirrors-received-code
sed -e 's/payload |-> "constructor",/payload |-> "code_reason",/' \
    -e 's/^                      code |-> 1000\]$/                      code |-> InboundOutcome(class).code]/' \
    CloseModel.tla > mut/close-echo/CloseModel.tla
cp CloseModel.cfg mut/close-echo/CloseModel.cfg

# defect.close.one-byte-rejected
sed 's/    \[\] class = "one_byte" -> 1002/    [] class = "one_byte" -> 1005/' \
  CloseModel.tla > mut/close-onebyte/CloseModel.tla
cp CloseModel.cfg mut/close-onebyte/CloseModel.cfg

echo "=== mutation diffs (each must be exactly the declared one) ==="
for m in frame-liveness close-liveness frame-mask frame-alloc frame-length-site close-echo close-onebyte; do
  case "$m" in frame-*) MOD=FrameModel ;; close-*) MOD=CloseModel ;; esac
  echo "--- $m ---"
  diff "$MOD.tla" "mut/$m/$MOD.tla"
  diff "$MOD.cfg" "mut/$m/$MOD.cfg"
done

for m in frame-liveness close-liveness frame-mask frame-alloc frame-length-site close-echo close-onebyte; do
  case "$m" in frame-*) MOD=FrameModel ;; close-*) MOD=CloseModel ;; esac
  echo "=================== MUTANT $m ($MOD) ==================="
  ( cd "mut/$m" && java -cp /home/agent/tlc/tla2tools.jar tlc2.TLC -config "$MOD.cfg" "$MOD" \
      > "/home/agent/tlc/out/tlc-mutant-$m.out" 2>&1 )
  echo "MUTANT_${m}_EXIT=$?"
  grep -E "Error: Invariant|Error: Temporal|Model checking completed" "out/tlc-mutant-$m.out" | head -3
done

echo "=== window end ==="
date -u +%Y-%m-%dT%H:%M:%SZ | tee out/window-end.txt
echo "=== pristine artifacts unchanged ==="
sha256sum FrameModel.tla FrameModel.cfg CloseModel.tla CloseModel.cfg
echo "=== out digests ==="
( cd out && sha256sum ./* > out-digests.sha256 && cat out-digests.sha256 )
