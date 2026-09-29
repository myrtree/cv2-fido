#!/usr/bin/gjs
const GLib = imports.gi.GLib;
let rule;
const polkit = {
    Result: { YES: 'yes', NO: 'no', AUTH_ADMIN: 'auth_admin' },
    addRule: function(callback) { rule = callback; }
};
const [ok, bytes] = GLib.file_get_contents(ARGV[0]);
if (!ok) throw new Error('could not read policy');
eval(new TextDecoder().decode(bytes));
if (typeof rule !== 'function') throw new Error('policy did not register a rule');

function check(user, groups, action, expected) {
    const subject = {
        user: user,
        isInGroup: function(group) { return groups.includes(group); }
    };
    const actual = rule({id: action}, subject);
    if (actual !== expected) {
        throw new Error(`${user} ${action}: expected ${expected}, got ${actual}`);
    }
}
const prefix = 'net.reactivated.fprint.device.';
check('cv2-fido', [], prefix + 'verify', polkit.Result.YES);
check('cv2-fido', [], prefix + 'setusername', polkit.Result.YES);
check('cv2-fido', [], prefix + 'enroll', polkit.Result.NO);
check('cv2-fido', [], 'org.example.unrelated', undefined);
check('alice', ['cv2-fido-users'], prefix + 'enroll', polkit.Result.AUTH_ADMIN);
check('alice', ['cv2-fido-users'], prefix + 'verify', undefined);
check('bob', [], prefix + 'enroll', undefined);
print('Polkit policy decisions passed');
