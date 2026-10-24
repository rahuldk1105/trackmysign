// Runs the GST portal's own handling of the local signer's frames against
// frames TrackMySign sent, for tests/run.sh.
//
//   node portal_compat.js <greeting.txt> <reply.txt> <version> <signature-out>
//
// The two handlers below are copied from the portal's JavaScript,
// uiassets/js/common/directives1.4.js (`emSignerConn` conn.onmessage and
// `dscAction` connection.onmessage), constants from common1.3.js
// (EM_ENTY_ID; LATEST_EM_VERSION is passed in, as it changes), as mirrored at
// https://github.com/sainandanbose3034/gst-offline-tool-linux (2026-03-20).
// Only the AngularJS/jQuery plumbing around them is replaced by stubs.
"use strict";
const fs = require("fs");

const [greetingFile, replyFile, version, signatureOut] = process.argv.slice(2);
const constants = { LATEST_EM_VERSION: version, EM_ENTY_ID: "gstnInfy" };
const $ = () => ({ getConstant: (k) => constants[k], blockPage: () => {} });
$.map = (arr, fn) => arr.map(fn);

// --- from emSignerConn: the greeting check -------------------------------
function greetingCheck(e) {
  let result;
  const deferred = { resolve: (v) => (result = v) };
  const conn = { connected: true };
  /* begin portal code */
  var em_data = e.data.split("\n"),
    verfy_length = 0;
  $.map(em_data, function (i) {
    var xd = i.split("=");
    if (xd.length > 0) {
      if ((xd[0].trim() == "version" && xd[1].trim() == $().getConstant("LATEST_EM_VERSION")) || (xd[0].trim() == "ID" && xd[1].trim() == $().getConstant("EM_ENTY_ID"))) {
        verfy_length++;
      }
    }
  });
  if (verfy_length == 2) {
    deferred.resolve(conn);
  } else {
    //conn.close();
    deferred.resolve({
      status: "500",
      error: "Please install and use correct version of emSigner",
    });
  }
  /* end portal code */
  return result;
}

// --- from dscAction: the reply handler -----------------------------------
function replyHandler(resp) {
  const outcome = {};
  const scope = { setError: (m) => (outcome.error = m), $apply: (f) => f(), panAuth: "ABCDE1234F" };
  const ajax = { post: (url, params) => ((outcome.posted = params), { then: () => {} }) };
  const dhash = "";
  /* begin portal code */
  if (resp.data === "signing canceled" || resp.data === "signing failed") {
    $().blockPage(false);
    //console.log("WebSocket Closed");
    scope.$apply(function () {
      scope.setError("Signing Cancelled");
    });
  } else if (resp.data.indexOf("status = success") > -1) {
    //console.log("Opened");
    $().blockPage(false);
  } else {
    if (resp.data.substring(11, resp.data.indexOf("SerialNo") - 1) != "") {
      var params = {
        hContent: dhash,
        emSignData: resp.data.substring(11, resp.data.indexOf("SerialNo") - 1),
        pan: scope.panAuth,
        refNum: Math.floor(Math.random() * 10000),
        formJson: scope.rPayload,
      };
      ajax.post(scope.signUrl, params, {}, function () {});
    }
  }
  /* end portal code */
  return outcome;
}

let failed = false;
const check = (ok, what) => {
  console.log(`${ok ? "PASS" : "FAIL"} portal JS: ${what}`);
  if (!ok) failed = true;
};

const greeting = fs.readFileSync(greetingFile, "utf8");
check(greetingCheck({ data: greeting }).connected === true, `greeting accepted for version ${version}`);
constants.LATEST_EM_VERSION = "0.0";
check(greetingCheck({ data: greeting }).status === "500", "greeting refused for another version");
constants.LATEST_EM_VERSION = version;

const reply = fs.readFileSync(replyFile, "utf8");
const out = replyHandler({ data: reply });
const sig = out.posted && out.posted.emSignData;
check(!out.error && /^[A-Za-z0-9_-]{100,}$/.test(sig || ""), "reply yields a signature to post");
for (const bare of ["signing canceled", "signing failed"]) {
  check(replyHandler({ data: bare }).error === "Signing Cancelled", `"${bare}" shown as cancelled`);
}
if (sig) fs.writeFileSync(signatureOut, sig);
process.exit(failed ? 1 : 0);
