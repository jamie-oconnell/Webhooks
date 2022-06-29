require("url").URL;
const crypto = require("crypto");
const https = require("https");

function get_sha256_digest(data) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify(data))
    .digest("base64");
}

function signKey(key, msg) {
  return crypto.createHmac("sha256", key).update(msg).digest("base64");
}

function get_auth_header(hdrs, signed_msg, key_id) {
  let auth_str = "Signature";

  auth_str =
    auth_str +
    " " +
    'keyId="' +
    key_id +
    '", ' +
    'algorithm="' +
    "hmac-sha256" +
    '",';

  auth_str = auth_str + ' headers="(request-target)';

  for (const [key, value] of Object.entries(hdrs)) {
    auth_str = auth_str + " " + key.toLowerCase();
  }
  auth_str = auth_str + '"';

  auth_str = auth_str + "," + ' signature="' + signed_msg + '"';

  return auth_str;
}

function prepare_str_to_sign(req_tgt, hdrs) {
  let sign_str = "";
  sign_str = sign_str + "(request-target): " + req_tgt + "\n";

  let i = 0;
  for (const [key, value] of Object.entries(hdrs)) {
    sign_str = sign_str + key.toLowerCase() + ": " + value;
    if (i < Object.keys(hdrs).length - 1) {
      sign_str = sign_str + "\n";
    }
    i += 1;
  }

  return sign_str;
}

function verify_auth_header(req, context) {
  let valid = true;
  let error = "";

  if (req["headers"]["authorization"]) {
    actual_auth = req["headers"]["authorization"];
    context.log(">>   actual_auth:", actual_auth);
  } else {
    context.log.error("No auth header to verify");
    valid = false;
    error = "No auth header to verify";
    return { valid, error };
  }

  // Generate the expected authorization header
  let host_uri = process.env["INTERSIGHT_WEBHOOK_URI"];
  let target_host = new URL(host_uri).hostname;
  let target_path = new URL(host_uri).pathname;
  let request_target = "post" + " " + target_path;

  let body_digest = get_sha256_digest(req["body"]);

  let auth_header = {
    Host: target_host,
    Date: req["headers"]["date"],
    Digest: "SHA-256=" + body_digest,
    "Content-Type": "application/json",
    "Content-Length": JSON.stringify(req["body"]).length,
  };

  if (auth_header["Digest"] != req["headers"]["digest"]) {
    context.log.error("Unexpected body digest");
    valid = false;
    error = "Unexpected body digest";
    return { valid, error };
  }

  let string_to_sign = prepare_str_to_sign(request_target, auth_header);
  context.log(">> string to sign:", string_to_sign);
  let webhook_secret = process.env["INTERSIGHT_WEBHOOK_SECRET"];
  let sign = signKey(webhook_secret, string_to_sign);
  let key_id = process.env["INTERSIGHT_WEBHOOK_KEY_ID"];

  let expected_auth = get_auth_header(auth_header, sign, key_id);
  context.log(">> expected auth:", expected_auth);

  if (expected_auth != actual_auth) {
    context.log.error("Authorization failed");
    valid = false;
    error = "Authorization failed";
    return { valid, error };
  }

  return { valid, error };
}

function datadog_event(data, context) {
  return new Promise((resolve, reject) => {
    data = JSON.stringify(data);
    context.log(data);
    var options = {
      host: "api.datadoghq.com",
      port: "443",
      path: "/api/v1/events",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "DD-API-KEY": process.env["DATADOG_API_KEY"],
      },
    };

    const req = https
      .request(options, (res) => {
        let data = "";

        res.on("data", (chunk) => {
          data += chunk;
        });

        res.on("end", () => {
          resolve({
            status: res.statusCode,
            body: JSON.parse(data),
          });
        });
      })
      .on("error", (err) => {
        context.log.error("Error: ", err.message);
        reject(err.message);
      });

    req.write(data);
    req.end();
  });
}

module.exports = async function (context, req) {
  context.log("Recieved post request");

  context.log("Verifying auth header");
  $verify = verify_auth_header(req, context);

  if (!$verify.valid) {
    context.res = {
      status: 401,
      body: $verify.error,
    };
  } else {
    let alarm_event = req["body"]["Event"];
    context.log(">> alarm_event:", alarm_event);

    if (alarm_event) {
      context.log(
        ">> posting alarm:",
        alarm_event["LastTransitionTime"],
        alarm_event["AffectedMoDisplayName"],
        alarm_event["Code"],
        alarm_event["Moid"],
        alarm_event["Severity"],
        alarm_event["Description"],
        "to datadog"
      );

      const severities = {
        Warning: "warning",
        Critical: "error",
        Info: "info",
        Cleared: "success",
      };

      let severity = severities[alarm_event["Severity"]];
      let createdTime = Math.floor(
        new Date(alarm_event["CreateTime"]).getTime() / 1000
      );

      try {
        let result = await datadog_event({
          title: alarm_event["Description"],
          text:
            alarm_event["AffectedMoDisplayName"] + " " + alarm_event["Code"],
          alert_type: severity,
          tags: [
            "moid:" + alarm_event["Moid"],
            "intersight_name:" + alarm_event["Name"],
          ],
          date_happened: createdTime,
          agregation_key: alarm_event["AffectedMoId"],
        });
        context.log(">> result:", result);
        if (result.status == 202) {
          context.res = {
            status: 200,
            body: "Sucessfully posted to datadog",
          };
        } else {
          context.res = {
            status: 500,
            body: "Failed to post to datadog",
          };
        }
      } catch (error) {
        context.res = {
          status: 500,
          body: "Failed to post to datadog",
        };
      }
    } else {
      context.res = {
        status: 200,
        body: "No alarm event to post to datadog",
      };
    }
  }
};
