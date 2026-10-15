// Deferred custom action WriteAgentConfig (installers/windows/Product.wxs).
// Writes C:\ProgramData\OfficeHQ\MDM\config.json from CustomActionData
//
//   <directory>|<collectionUrl>|<ownership>|<tenantId>|<clientId>|<enrollToken>
//
// in the shape installers/windows/config-writer.mjs renders and
// agent/internal/config.Load reads: tenantId and clientId only when set, the
// legacy enrollmentToken only when non-empty, ownership "officehq" unless
// "byoc" was chosen. The token is last, so a "|" inside it survives.
// Runs under the Windows Installer JScript host (ES3: no JSON object), which
// WiX v4+ takes by ScriptSourceFile.
function jsonString(value) {
  return '"' + value.replace(/\\/g, "\\\\").replace(/"/g, "\\\"") + '"';
}

var data = Session.Property("CustomActionData");
var fields = [];
for (var i = 0; i < 5; i++) {
  var separator = data.indexOf("|");
  if (separator < 0) {
    fields.push(data);
    data = "";
  } else {
    fields.push(data.substring(0, separator));
    data = data.substring(separator + 1);
  }
}
fields.push(data);

var directory = fields[0];
var collectionUrl = fields[1];
var ownership = fields[2] === "byoc" ? "byoc" : "officehq";
var tenantId = fields[3];
var clientId = fields[4];
var enrollToken = fields[5];

var fso = new ActiveXObject("Scripting.FileSystemObject");
if (!fso.FolderExists(directory)) {
  var parent = fso.GetParentFolderName(directory);
  if (parent.length > 0 && !fso.FolderExists(parent)) {
    fso.CreateFolder(parent);
  }
  fso.CreateFolder(directory);
}

var lines = [
  "{",
  '  "collectionUrl": ' + jsonString(collectionUrl) + ",",
  '  "ownership": ' + jsonString(ownership) + ","
];
if (tenantId.length > 0) {
  lines.push('  "tenantId": ' + jsonString(tenantId) + ",");
}
if (clientId.length > 0) {
  lines.push('  "clientId": ' + jsonString(clientId) + ",");
}
if (enrollToken.length > 0) {
  lines.push('  "enrollmentToken": ' + jsonString(enrollToken) + ",");
}
lines.push('  "checkInIntervalSeconds": 900,');
lines.push('  "logLevel": "info"');
lines.push("}");
lines.push("");

var file = fso.CreateTextFile(fso.BuildPath(directory, "config.json"), true);
file.Write(lines.join("\r\n"));
file.Close();
