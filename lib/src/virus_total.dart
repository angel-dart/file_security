import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:angel_framework/angel_framework.dart';
import 'package:body_parser/body_parser.dart';
import 'package:charcode/ascii.dart';
import 'package:random_string/random_string.dart' as rs;

/// Scans incoming files using VirusTotal's API.
///
/// An error is thrown if the minimum number of positives (default: `3`) is found in the scan report.
///
/// Scans will be checked regularly based on the [checkInterval].
RequestMiddleware virusScanUploads(String apiKey,
        {int minPositives, Duration checkInterval}) =>
    new _VirusTotal(
        apiKey, minPositives ?? 3, checkInterval ?? new Duration(seconds: 5));

class _VirusTotal extends AngelMiddleware {
  static const String ENDPOINT = 'https://www.virustotal.com/vtapi/v2';
  final String apiKey;
  final Duration checkInterval;
  final HttpClient client = new HttpClient();
  final int minPositives;

  _VirusTotal(this.apiKey, this.minPositives, this.checkInterval);

  @override
  Future<bool> call(RequestContext req, ResponseContext res) async {
    for (var file in await req.lazyFiles()) {
      await scanFile(file);
    }

    client.close(force: true);
    return true;
  }

  writeln(StringBuffer buf, [String text]) {
    buf
      ..write(text ?? '')
      ..writeCharCode($cr)
      ..writeCharCode($lf);
  }

  scanFile(FileUploadInfo file) async {
    var rq = await client.openUrl('POST', Uri.parse('$ENDPOINT/file/scan'));
    var boundary = '-----' + rs.randomAlphaNumeric(24);

    var buf = new StringBuffer();

    // Add API Key
    writeln(buf, boundary);
    writeln(buf, 'Content-Disposition: form-data; name="apikey"');
    writeln(buf);
    writeln(buf, apiKey);

    // Add actual file
    writeln(buf, boundary);
    writeln(buf,
        'Content-Disposition: form-data; name="file"; filename="${file.filename}"');
    writeln(buf, 'Content-Type: ${file.mimeType}');
    writeln(buf);
    file.data.forEach(buf.writeCharCode);
    writeln(buf);

    // Finish it
    writeln(buf, '$boundary--');

    rq.headers
      ..set(HttpHeaders.ACCEPT, ContentType.JSON.mimeType)
      ..set(HttpHeaders.ACCEPT_ENCODING, 'gzip')
      ..set(HttpHeaders.CONTENT_LENGTH, buf.length)
      ..set(
          HttpHeaders.CONTENT_TYPE, 'multipart/form-data; boundary=$boundary');
    rq.write(buf.toString());

    var res = await rq.close();
    var json = JSON.decode(await res.transform(UTF8.decoder).join());
    String scanId = json['scan_id'];

    var c = new Completer();

    new Timer.periodic(checkInterval, (_) async {
      var rq = await client.openUrl('POST', Uri.parse('$ENDPOINT/url/report'));

      var bodyFields = {'apikey': apiKey, 'resource': scanId};

      var data = bodyFields.keys.fold<List<String>>(
          [],
          (out, key) => out
            ..add('$key=' + Uri.encodeComponent(bodyFields[key]))).join('&');

      rq.headers
        ..set(HttpHeaders.ACCEPT, ContentType.JSON.mimeType)
        ..set(HttpHeaders.ACCEPT_ENCODING, 'gzip')
        ..set(HttpHeaders.CONTENT_LENGTH, data.length);
      rq.write(data);

      var res = await rq.close();
      var json = JSON.decode(await res.transform(UTF8.decoder).join());

      if (json['positives'] is int) {
        int positives = json['positives'];

        if (positives >= minPositives)
          c.completeError(new AngelHttpException.conflict(
              message: 'Malicious upload blocked.'));
        else
          c.complete();
      }
    });

    return await c.future;
  }
}
