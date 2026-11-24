/* Paths and queries are ones FastAPI 0.165 on uvicorn 0.54, the stack MONAI
 * Label runs on, routed to the handler, with what the handler then saw. */
export const port = 8000;

export default function ({ f, run, stream, ok, progs, bytes, show, root, readFileSync, req, get, post, part, multipart, B, tomcatSpellings }) {
  const web = { dport: port };
  const put = (t) => req("PUT", t, `Content-Type: multipart/form-data; boundary=${B}\r\n`, part(`name="file"; filename="scan.nii.gz"`, "\x5c\x01\x00\x00../", "application/gzip"));
  /* each of these reached the handler with a path that leaves the datastore */
  for (const q of ["image=../../../tmp/x", "image=%2e%2e%2f%2e%2e%2ftmp%2fx", "image=..%2f..%2ftmp%2fx", "image=%2E%2E/tmp/x", "image=.%2e/tmp/x", "image=..%5c..%5ctmp", "image=/tmp/x", "image=%2ftmp%2fx",
    "im%61ge=../tmp/x", "image=ok&image=../tmp/x", "x=1&image=../tmp/x", "image=a/../../tmp/x", "image=..;/tmp/x"])
    run(f, `PUT /datastore/image?${q}`, put("/datastore/image?" + q), "rst(monai_traversal)", web);
  /* each of these paths reached the same handler */
  for (const p of ["/%64atastore/image", "/datastore/imag%65", "/datastore%2fimage", "/datastore%2Fimage"]) run(f, `PUT ${p}?image=../x`, put(p + "?image=../x"), "rst(monai_traversal)", web);
  run(f, "the label route, traversal in the tag", put("/datastore/label?image=a&tag=../x"), "rst(monai_traversal)", web);
  run(f, "the info route", put("/datastore/image/info?image=../x"), "rst(monai_traversal)", web);
  run(f, "a second ? in the query", put("/datastore/image?a=1?image=x"), "rst(monai_traversal)", web);
  run(f, "padding before the traversal", put("/datastore/image?x=" + "a".repeat(400) + "&image=../x"), "rst(monai_traversal)", web);

  run(f, "an ordinary upload", put("/datastore/image?image=scan_001.nii.gz"), "pass", web);
  run(f, "a label upload", put("/datastore/label?image=scan_001&tag=final"), "pass", web);
  run(f, "fetch an image", get("/datastore/image?image=scan_001"), "pass", web);
  run(f, "image info", get("/datastore/image/info?image=scan_001"), "pass", web);
  run(f, "datastore listing", get("/datastore/?output=all"), "pass", web);
  run(f, "the dataset route", get("/datastore/dataset"), "pass", web);
  run(f, "inference on another route, a slash in its query", req("POST", "/infer/segmentation?image=scan_001&output=image/nii"), "pass", web);
  run(f, "a 64-character DICOM UID and a tag", put("/datastore/label?image=1.2.840.113619.2.55.3.604688119.971.1407250023.123.4567890123456&tag=final"), "pass", web);
  run(f, "another port", put("/datastore/image?image=../x"), "pass", { dport: 80 });
}
