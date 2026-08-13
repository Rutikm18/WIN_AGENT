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
        ['X', 'PURGE_ON_UNINSTALL'],
        ['G', 'GUI_MANAGER_REQUIRED']
    ];
    var fields = [];
    for (var item = 0; item < properties.length; item++) {
        fields.push(jsonQuote(properties[item][0]) + ':' +
            jsonQuote(Session.Property(properties[item][1])));
    }
    var json = '{' + fields.join(',') + '}';
    return base64Encode(utf8Bytes(json));
}

function isValidBareIpv4(value) {
    if (!/^\d+(?:\.\d+){3}$/.test(value)) {
        return false;
    }
    var octets = value.split('.');
    for (var index = 0; index < octets.length; index++) {
        if (octets[index].length > 1 && octets[index].charAt(0) === '0') {
            return false;
        }
        var number = parseInt(octets[index], 10);
        if (number < 0 || number > 255) {
            return false;
        }
    }
    return true;
}

// Validate at the manager dialog's Next event so a bad numeric address never
// reaches the later pages or the elevated configuration action. DNS names and
// absolute HTTP(S) URLs remain valid deployment inputs.
function ValidateManagerAddressUI() {
    var value = String(Session.Property('MANAGER_URL') || '').replace(/^\s+|\s+$/g, '');
    Session.Property('MANAGER_URL') = value;
    var valid = value.length > 0;
    if (/^\d/.test(value) && value.indexOf('://') < 0) {
        valid = isValidBareIpv4(value);
    }
    Session.Property('MANAGER_ADDRESS_VALID') = valid ? '1' : '0';
    return 1;
}

// Capture final full-UI values in the interactive MSI client. The uppercase
// Secure+Hidden property is transferred to the elevated execute server.
function StageConfigDataFromUI() {
    // This action is published directly by AttackLensSecurityDlg.Next, so it
    // executes before the custom dialog stack is left. Mark the payload as a
    // GUI install: an empty manager must be treated as handoff corruption,
    // never as an intentional offline/silent deployment.
    Session.Property('GUI_MANAGER_REQUIRED') = '1';
    Session.Property('ATTACKLENS_CONFIG_DATA') = buildConfigData();
    return 1; // msiDoActionStatusSuccess / IDOK
}

function PrepareConfigData() {
    // Defense in depth for a full-UI first install/major upgrade. If dialog
    // capture was skipped unexpectedly, preserve enough intent for the
    // elevated generator to fail closed rather than write url = "".
    if (!Session.Property('GUI_MANAGER_REQUIRED') &&
            Session.Property('UILevel') === '5' &&
            !Session.Property('Installed')) {
        Session.Property('GUI_MANAGER_REQUIRED') = '1';
    }
    // Rebuild in the elevated execute session from the uppercase Secure
    // properties that Windows Installer transferred from the UI client. A
    // 2.0.22 endpoint reproduction proved that the staged opaque payload can
    // be stale even while MANAGER_URL itself is present in the server session.
    // The dialog-bound payload remains useful as a transfer/audit guard, but
    // it must never override the authoritative server-side properties.
    Session.Property('CA_WriteConfig') = buildConfigData();
    return 1; // msiDoActionStatusSuccess / IDOK
}
