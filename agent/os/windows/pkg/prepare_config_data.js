// Convert interactive/silent MSI properties into opaque CustomActionData for
// the deferred SYSTEM configuration action. A deferred EXE cannot query the
// original MSI session, so the data must be prepared while it is available.
// Base64 prevents quotes, semicolons and Unicode from becoming command syntax.

function jsonQuote(value) {
    var text = String(value || "");
    var out = '"';
    for (var index = 0; index < text.length; index++) {
        var code = text.charCodeAt(index);
        var character = text.charAt(index);
        if (character === '"') {
            out += '\\"';
        } else if (character === '\\') {
            out += '\\\\';
        } else if (code === 8) {
            out += '\\b';
        } else if (code === 9) {
            out += '\\t';
        } else if (code === 10) {
            out += '\\n';
        } else if (code === 12) {
            out += '\\f';
        } else if (code === 13) {
            out += '\\r';
        } else if (code < 32) {
            out += '\\u' + ('0000' + code.toString(16)).slice(-4);
        } else {
            out += character;
        }
    }
    return out + '"';
}

function utf8Bytes(text) {
    var bytes = [];
    for (var index = 0; index < text.length; index++) {
        var code = text.charCodeAt(index);
        if (code >= 0xD800 && code <= 0xDBFF && index + 1 < text.length) {
            var low = text.charCodeAt(index + 1);
            if (low >= 0xDC00 && low <= 0xDFFF) {
                code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                index++;
            }
        }
        if (code < 0x80) {
            bytes.push(code);
        } else if (code < 0x800) {
            bytes.push(0xC0 | (code >> 6));
            bytes.push(0x80 | (code & 0x3F));
        } else if (code < 0x10000) {
            bytes.push(0xE0 | (code >> 12));
            bytes.push(0x80 | ((code >> 6) & 0x3F));
            bytes.push(0x80 | (code & 0x3F));
        } else {
            bytes.push(0xF0 | (code >> 18));
            bytes.push(0x80 | ((code >> 12) & 0x3F));
            bytes.push(0x80 | ((code >> 6) & 0x3F));
            bytes.push(0x80 | (code & 0x3F));
        }
    }
    return bytes;
}

function base64Encode(bytes) {
    var alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var output = '';
    for (var index = 0; index < bytes.length; index += 3) {
        var first = bytes[index];
        var second = index + 1 < bytes.length ? bytes[index + 1] : 0;
        var third = index + 2 < bytes.length ? bytes[index + 2] : 0;
        output += alphabet.charAt(first >> 2);
        output += alphabet.charAt(((first & 3) << 4) | (second >> 4));
        output += index + 1 < bytes.length
            ? alphabet.charAt(((second & 15) << 2) | (third >> 6)) : '=';
        output += index + 2 < bytes.length ? alphabet.charAt(third & 63) : '=';
    }
    return output;
}

function buildConfigData() {
    var properties = [
        ['U', 'MANAGER_URL'],
        ['I', 'MANAGER_IP'],
        ['P', 'MANAGER_PORT'],
        ['V', 'TLS_VERIFY'],
        ['H', 'ALLOW_INSECURE_TRANSPORT'],
        ['C', 'CA_BUNDLE'],
        ['S', 'SPKI_PIN'],
        ['T', 'ENROLL_TOKEN'],
        ['N', 'AGENT_NAME'],
        ['R', 'COLLECTION_PROFILE'],
        ['K', 'PRESERVE_STATE'],
        ['X', 'PURGE_ON_UNINSTALL']
    ];
    var fields = [];
    for (var item = 0; item < properties.length; item++) {
        fields.push(jsonQuote(properties[item][0]) + ':' +
            jsonQuote(Session.Property(properties[item][1])));
    }
    var json = '{' + fields.join(',') + '}';
    return base64Encode(utf8Bytes(json));
}

// Capture final full-UI values in the interactive MSI client. The uppercase
// Secure+Hidden property is transferred to the elevated execute server.
function StageConfigDataFromUI() {
    Session.Property('ATTACKLENS_CONFIG_DATA') = buildConfigData();
    return 1; // msiDoActionStatusSuccess / IDOK
}

function PrepareConfigData() {
    var encoded = Session.Property('ATTACKLENS_CONFIG_DATA');
    if (!encoded) {
        // Silent/basic-UI installs do not run the full UI sequence.
        encoded = buildConfigData();
    }
    Session.Property('CA_WriteConfig') = encoded;
    return 1; // msiDoActionStatusSuccess / IDOK
}
