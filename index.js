const Database = require('better-sqlite3');
const debug = require('debug')('udger-nodejs');
const Address6 = require('ip-address').Address6;
const Address4 = require('ip-address').Address4;
const utils = require('./utils');
const fs = require('fs-extra');
const dotProp = require('dot-prop');
const path = require('path');
const RandExp = require('randexp');

/** Class exposing udger parser methods */
class UdgerParser {

    /**
     * Load udger SQLite3 database.
     * @param {string} file - full path to udgerdb_v3.dat
     */
    constructor(file) {
        this.data = require('./out/udgerdb_v3');
        this.db = new Database(file, { readonly: true, fileMustExist: true });
        this.file = file;
        this.ip = null;
        this.ua = null;

        this.cacheEnable = false;
        this.cacheMaxRecords = 4000;
        this.cache = {};
        this.keyCache = '';

        this.defaultRet = fs.readJsonSync(path.resolve(__dirname + '/defaultResult.json'));
        this.retUa = {};
        this.retIp = {};
    }

    findBy(table, fn) {
        let { data, columns } = this.data[table];
        return data.find(v => fn(v, columns));
    }

    filterBy(table, fn) {
        let { data, columns } = this.data[table];
        return data.filter(v => fn(v, columns));
    }

    map({ table, row, keys, rename }) {
        if (!row) return {};
        let { columns } = this.data[table];
        let ret = keys.reduce((acc, key) => {
            acc[key] = row[columns[key]];
            return acc;
        }, {});
        if (rename) {
            for (let [k1, k2] of Object.entries(rename)) {
                ret[k2] = ret[k1];
                delete ret[k1];
            }
        }
        return ret;
    }

    /**
     * Connect (reconnect) sqlite database
     * @return {Boolean} true if db has been opened, false if already connected
     */
    connect() {
        if (!this.db) {
            this.db = new Database(this.file, { readonly: true, fileMustExist: true });
            return true;
        }
        return false;
    }

    /**
     * Disconnect sqlite database, avoid read/write conflict
     * see https://github.com/udger/udger-updater-nodejs/issues/5
     * @return {Boolean} true if db has been closed, false if no db opened
     */
    disconnect() {
        if (this.db) {
            this.db.close();
            this.db = null;
            return true;
        }
        return false;
    }

    /**
     * Initialize User-Agent or IP(v4/v6), or both
     * @param {Object} data - An object
     * @param {String} data.ua - User-Agent
     * @param {String} data.ip - IP Address
     */
    set(data) {

        const help = 'set() is waiting for an object having only ip and/or ua attribute';

        if (!data) {
            throw new Error(help);
        }

        if (typeof data === 'string') {
            throw new Error(help);
        }

        for (const key in data) {
            if (key === 'ua') {
                this.ua = data.ua;
            } else if (key === 'ip') {
                this.ip = data.ip.toLowerCase();
            } else {
                throw new Error(help);
            }
        }

        this.keyCache = '';

        if (this.cacheEnable) {
            if (this.ip) this.keyCache = this.ip;
            if (this.ua) this.keyCache += this.ua;
        }

        this.retUa = JSON.parse(JSON.stringify(this.defaultRet['user_agent']));
        this.retIp = JSON.parse(JSON.stringify(this.defaultRet['ip_address']));
    }

    /**
     * Activate cache
     * @param {Boolean} cache - true or false
     */
    setCacheEnable(cache) {
        this.cacheEnable = cache;
    }

    /**
     * Return if the cache is enable or not
     * @return {Boolean} true if the cache is enable, false if not
     */
    isCacheEnable() {
        return this.cacheEnable;
    }

    /**
     * Set Cache Size
     * @param {Number} records - the maximum number of items we want to keep in the cache
     */
    setCacheSize(records) {
        this.cacheMaxRecords = records;
    }

    /**
     * Check if a key exist in the cache
     * @param {Number} key - key can be UA or UA+IP
     * @return {Boolean} return true if the key exist in the cache, false if not
     */
    cacheKeyExist(key) {
        if (this.cache[key]) {
            return true;
        }
        return false;
    }

    /**
     * Return an item from the cache
     * @param {String} key - key can be UA or UA+IP
     * @return {Object} stored parser result
     */
    cacheRead(key, opts) {
        const ret = this.cache[key];
        if (opts && opts.json) {
            if (opts.full) {
                ret['fromCache'] = true;
            }
        } else {
            ret['from_cache'] = true;
        }
        return ret;
    }

    /**
     * Write an item into the cache
     * @param {String} key - key can be UA or UA+IP
     */
    cacheWrite(key, data) {
        if (this.cache[key]) {
            // already in the cache
            return;
        }

        this.cache[key] = data;

        debug('cache: store result of %s (length=%s)', key);
        debug('cache: entries count: %s/%s', (Object.keys(this.cache).length || 0), this.cacheMaxRecords);

        // warning, js object is used for performance reason
        // as opposite of php object, we can not use splice/pop stuff here
        // so, when an entry must be remove because the cache is full, we
        // can not determine which one will be removed
        while (Object.keys(this.cache).length > this.cacheMaxRecords) {
            debug('cache: removing entry', Object.keys(this.cache)[0]);
            delete this.cache[Object.keys(this.cache)[0]];
        }
    }

    /**
     * Clean the cache
     */
    cacheClean() {
        this.cache = {};
    }

    /**
     * Parse the User-Agent string
     * @param {String} ua - An User-Agent string
     */
    parseUa(ua, opts) {

        const rua = JSON.parse(JSON.stringify(this.retUa));
        const ruaJson = {};

        if (!ua) return {
            udger: rua,
            json: ruaJson
        };

        let q;
        let r;
        let e;

        let client_id = 0;
        let client_class_id = -1;
        let os_id = 0;
        let deviceclass_id = 0;

        debug('parse useragent string: START (useragent: ' + ua + ')');

        rua['ua_string'] = ua;
        rua['ua_class'] = 'Unrecognized';
        rua['ua_class_code'] = 'unrecognized';

        dotProp.set(ruaJson, 'ua.string', ua);
        if (opts.full) {
            dotProp.set(ruaJson, 'ua.class.name', 'Unrecognized');
            dotProp.set(ruaJson, 'ua.class.code', 'unrecognized');
        } else {
            dotProp.set(ruaJson, 'ua.class', 'unrecognized');
        }

        ////////////////////////////////////////////////
        // search for crawlers
        ////////////////////////////////////////////////

        q = this.findBy('udger_crawler_list', (row, { ua_string }) => row[ua_string] === ua);

        if (q) {

            r = this.map({
                table: 'udger_crawler_list',
                row: q,
                keys: [
                    'id', 'name', 'ver', 'ver_major', 'last_seen', 'respect_robotstxt',
                    'family', 'family_code', 'family_homepage', 'family_icon',
                    'vendor', 'vendor_code', 'vendor_homepage', 'class_id'
                ],
                rename: { id: 'botid' }
            });
            r = {
                ...r, ...this.map({
                    table: 'udger_crawler_class',
                    row: this.data.udger_crawler_class.data[r.class_id],
                    keys: ['crawler_classification', 'crawler_classification_code']
                })
            };

            debug('parse useragent string: crawler found');

            client_class_id = 99;

            // UDGER FORMAT
            rua['ua_class'] = 'Crawler';
            rua['ua_class_code'] = 'crawler';
            rua['ua'] = r['name'] || '';
            rua['ua_version'] = r['ver'] || '';
            rua['ua_version_major'] = r['ver_major'] || '';
            rua['ua_family'] = r['family'] || '';
            rua['ua_family_code'] = r['family_code'] || '';
            rua['ua_family_homepage'] = r['family_homepage'] || '';
            rua['ua_family_vendor'] = r['vendor'] || '';
            rua['ua_family_vendor_code'] = r['vendor_code'] || '';
            rua['ua_family_vendor_homepage'] = r['vendor_homepage'] || '';
            rua['ua_family_icon'] = r['family_icon'] || '';
            rua['ua_family_info_url'] = 'https://udger.com/resources/ua-list/bot-detail?bot=' + (r['family'] || '') + '#id' + (r['botid'] || '');

            rua['crawler_last_seen'] = r['last_seen'] || '';
            rua['crawler_category'] = r['crawler_classification'] || '';
            rua['crawler_category_code'] = r['crawler_classification_code'] || '';
            rua['crawler_respect_robotstxt'] = r['respect_robotstxt'] || '';

            // JSON FORMAT
            rua['ua'] && dotProp.set(ruaJson, 'ua.name', rua['ua']);

            if (opts.full) {
                dotProp.set(ruaJson, 'ua.class.name', 'Crawler');
                dotProp.set(ruaJson, 'ua.class.code', 'crawler');
                rua['ua_version'] && dotProp.set(ruaJson, 'ua.version.current', rua['ua_version']);
                rua['ua_version_major'] && dotProp.set(ruaJson, 'ua.version.major', rua['ua_version_major']);

                rua['ua_family'] && dotProp.set(ruaJson, 'ua.family.name', rua['ua_family']);
                rua['ua_family_code'] && dotProp.set(ruaJson, 'ua.family.code', rua['ua_family_code']);
                rua['ua_family_homepage'] && dotProp.set(ruaJson, 'ua.family.homepage', rua['ua_family_homepage']);
                rua['ua_family_vendor'] && dotProp.set(ruaJson, 'ua.family.vendor.name', rua['ua_family_vendor']);
                rua['ua_family_vendor_code'] && dotProp.set(ruaJson, 'ua.family.vendor.code', rua['ua_family_vendor_code']);
                rua['ua_family_homepage'] && dotProp.set(ruaJson, 'ua.family.vendor.homepage', rua['ua_family_homepage']);
                rua['ua_family_icon'] && dotProp.set(ruaJson, 'ua.family.icon', rua['ua_family_icon']);
                rua['ua_family'] && r['botid'] && dotProp.set(ruaJson, 'ua.family.infoUrl', rua['ua_family_info_url']);

            } else {
                dotProp.set(ruaJson, 'ua.class', 'crawler');
                rua['ua_family_code'] && dotProp.set(ruaJson, 'ua.family.code', rua['ua_family_code']);
                rua['ua_family_homepage'] && dotProp.set(ruaJson, 'ua.family.homepage', rua['ua_family_homepage']);
                rua['ua_family_vendor_code'] && dotProp.set(ruaJson, 'ua.family.vendor', rua['ua_family_vendor_code']);
            }

            rua['crawler_last_seen'] && dotProp.set(ruaJson, 'crawler.lastSeen', rua['crawler_last_seen']);

            if (opts.full) {
                rua['crawler_category'] && dotProp.set(ruaJson, 'crawler.category.name', rua['crawler_category']);
                rua['crawler_category_code'] && dotProp.set(ruaJson, 'crawler.category.code', rua['crawler_category_code']);
                rua['crawler_respect_robotstxt'] && dotProp.set(ruaJson, 'crawler.respectRobotsTxt', rua['crawler_respect_robotstxt']);
            } else {
                rua['crawler_category_code'] && dotProp.set(ruaJson, 'crawler.category', rua['crawler_category_code']);
            }
        } else {

            q = this.data.udger_client_regex.columns.regstring;

            for (r of this.data.udger_client_regex.data) {
                e = ua.match(utils.phpRegexpToJs(r[q]));
                if (e) {

                    r = this.map({
                        table: 'udger_client_regex',
                        row: r,
                        keys: ['client_id', 'regstring']
                    })
                    r = {
                        ...r, ...this.map({
                            table: 'udger_client_list',
                            row: this.data.udger_client_list.data[r.client_id],
                            keys: ['id', 'class_id', 'name', 'name_code', 'homepage', 'icon', 'icon_big', 'engine', 'vendor', 'vendor_code', 'vendor_homepage', 'uptodate_current_version'],
                            rename: { id: 'client_id' }
                        })
                    }
                    r = {
                        ...r, ...this.map({
                            table: 'udger_client_class',
                            row: this.data.udger_client_class.data[r.class_id],
                            keys: ['id', 'client_classification', 'client_classification_code'],
                            rename: { id: 'class_id' }
                        })
                    }

                    debug('parse useragent string: client found');

                    client_id = r['client_id'];
                    client_class_id = r['class_id'];

                    rua['ua_class'] = r['client_classification'];
                    rua['ua_class_code'] = r['client_classification_code'];

                    if (opts.full) {
                        dotProp.set(ruaJson, 'ua.class.name', rua['ua_class']);
                        dotProp.set(ruaJson, 'ua.class.code', rua['ua_class_code']);
                    } else {
                        dotProp.set(ruaJson, 'ua.class', rua['ua_class_code']);
                    }
                    if (e[1]) {
                        rua['ua'] = r['name'] + ' ' + e[1];
                        rua['ua_version'] = e[1];
                        rua['ua_version_major'] = e[1].split('.')[0];
                    } else {
                        rua['ua'] = r['name'];
                        rua['ua_version'] = '';
                        rua['ua_version_major'] = '';
                    }

                    if (rua['ua']) {
                        dotProp.set(ruaJson, 'ua.name', rua['ua']);
                    } else {
                        dotProp.delete(ruaJson, 'ua.name');
                    }

                    if (opts.full) {
                        if (rua['ua_version']) {
                            dotProp.set(ruaJson, 'ua.version.current', rua['ua_version']);
                        } else {
                            dotProp.delete(ruaJson, 'ua.version.current');
                        }

                        if (rua['ua_version_major']) {
                            dotProp.set(ruaJson, 'ua.version.current', rua['ua_version_major']);
                        } else {
                            dotProp.delete(ruaJson, 'ua.version.current');
                        }
                    }

                    rua['ua_uptodate_current_version'] = r['uptodate_current_version'] || '';
                    rua['ua_family'] = r['name'] || '';
                    rua['ua_family_code'] = r['name_code'] || '';
                    rua['ua_family_homepage'] = r['homepage'] || '';
                    rua['ua_family_vendor'] = r['vendor'] || '';
                    rua['ua_family_vendor_code'] = r['vendor_code'] || '';
                    rua['ua_family_vendor_homepage'] = r['vendor_homepage'] || '';
                    rua['ua_family_icon'] = r['icon'] || '';
                    rua['ua_family_icon_big'] = r['icon_big'] || '';
                    rua['ua_family_info_url'] = 'https://udger.com/resources/ua-list/browser-detail?browser=' + (r['name'] || '');
                    rua['ua_engine'] = r['engine'] || '';

                    if (opts.full) {
                        rua['ua_uptodate_current_version'] && dotProp.set(ruaJson, 'ua.uptodateCurrentVersion', rua['ua_uptodate_current_version']);
                        rua['ua_family'] && dotProp.set(ruaJson, 'ua.family.name', rua['ua_family']);
                        rua['ua_family_code'] && dotProp.set(ruaJson, 'ua.family.code', rua['ua_family_code']);
                        rua['ua_family_homepage'] && dotProp.set(ruaJson, 'ua.family.homepage', rua['ua_family_homepage']);
                        rua['ua_family_vendor'] && dotProp.set(ruaJson, 'ua.family.vendor.name', rua['ua_family_vendor']);
                        rua['ua_family_vendor_code'] && dotProp.set(ruaJson, 'ua.family.vendor.code', rua['ua_family_vendor_code']);
                        rua['ua_family_vendor_homepage'] && dotProp.set(ruaJson, 'ua.family.vendor.homepage', rua['ua_family_vendor_homepage']);
                        rua['ua_family_icon'] && dotProp.set(ruaJson, 'ua.family.icon', rua['ua_family_icon']);
                        rua['ua_family_icon_big'] && dotProp.set(ruaJson, 'ua.family.iconBig', rua['ua_family_icon_big']);
                        if (r['name']) {
                            dotProp.set(ruaJson, 'ua.family.infoUrl', rua['ua_family_info_url']);
                        }
                    } else {
                        rua['ua_family_code'] && dotProp.set(ruaJson, 'ua.family', rua['ua_family_code']);
                    }
                    rua['ua_engine'] && dotProp.set(ruaJson, 'ua.engine', rua['ua_engine']);

                    break;
                }
            }
        }

        ////////////////////////////////////////////////
        // os
        ////////////////////////////////////////////////

        q = this.data.udger_os_regex.columns.regstring;

        for (r of this.data.udger_os_regex.data) {
            e = ua.match(utils.phpRegexpToJs(r[q]));
            if (e) {

                r = this.map({
                    table: 'udger_os_regex',
                    row: r,
                    keys: ['os_id', 'regstring']
                })
                r = {
                    ...r, ...this.map({
                        table: 'udger_os_list',
                        row: this.data.udger_os_list.data[r.os_id],
                        keys: ['id', 'family', 'family_code', 'name', 'name_code', 'homepage', 'icon', 'icon_big', 'vendor', 'vendor_code', 'vendor_homepage'],
                        rename: { id: 'os_id' }
                    })
                }

                debug('parse useragent string: os found');

                os_id = r['os_id'];
                rua['os'] = r['name'] || '';
                rua['os_code'] = r['name_code'] || '';
                rua['os_homepage'] = r['homepage'] || '';
                rua['os_icon'] = r['icon'] || '';
                rua['os_icon_big'] = r['icon_big'] || '';
                rua['os_info_url'] = 'https://udger.com/resources/ua-list/os-detail?os=' + (r['name'] || '');
                rua['os_family'] = r['family'] || '';
                rua['os_family_code'] = r['family_code'] || '';
                rua['os_family_vendor'] = r['vendor'] || '';
                rua['os_family_vendor_code'] = r['vendor_code'] || '';
                rua['os_family_vendor_homepage'] = r['vendor_homepage'] || '';

                if (opts.full) {
                    rua['os'] && dotProp.set(ruaJson, 'os.name', rua['os']);
                    rua['os_code'] && dotProp.set(ruaJson, 'os.code', rua['os_code']);
                    rua['os_homepage'] && dotProp.set(ruaJson, 'os.homepage', rua['os_homepage']);
                    rua['os_icon'] && dotProp.set(ruaJson, 'os.icon', rua['os_icon']);
                    rua['os_icon_big'] && dotProp.set(ruaJson, 'os.iconBig', rua['os_icon_big']);
                    rua['os_info_url'] && dotProp.set(ruaJson, 'os.infoUrl', rua['os_info_url']);
                    rua['os_family'] && dotProp.set(ruaJson, 'os.family.name', rua['os_family']);
                    rua['os_family_code'] && dotProp.set(ruaJson, 'os.family.code', rua['os_family_code']);
                    rua['os_family_vendor'] && dotProp.set(ruaJson, 'os.family.vendor.name', rua['os_family_vendor']);
                    rua['os_family_vendor_code'] && dotProp.set(ruaJson, 'os.family.vendor.code', rua['os_family_vendor_code']);
                    rua['os_family_vendor_homepage'] && dotProp.set(ruaJson, 'os.family.vendor.homepage', rua['os_family_vendor_homepage']);
                } else {
                    rua['os_code'] && dotProp.set(ruaJson, 'os.code', rua['os_code']);
                    rua['os_family_code'] && dotProp.set(ruaJson, 'os.family', rua['os_family_code']);
                }
                break;
            }
        }

        ////////////////////////////////////////////////
        // client/os relation
        ////////////////////////////////////////////////

        if (os_id == 0 && client_id != 0) {

            q = this.findBy('udger_client_os_relation', (row, { client_id }) => row[client_id] === client_id);

            if (q) {

                r = this.map({
                    table: 'udger_client_os_relation',
                    row: r,
                    keys: ['os_id']
                });
                r = {
                    ...r, ...this.map({
                        table: 'udger_os_list',
                        row: this.data.udger_os_list.data[r.os_id],
                        keys: ['id', 'family', 'family_code', 'name', 'name_code', 'homepage', 'icon', 'icon_big', 'vendor', 'vendor_code', 'vendor_homepage'],
                        rename: { id: 'os_id' }
                    })
                }

                debug('parse useragent string: client os relation found');

                os_id = r['os_id'];
                rua['os'] = r['name'] || '';
                rua['os_code'] = r['name_code'] || '';
                rua['os_homepage'] = r['homepage'] || '';
                rua['os_icon'] = r['icon'] || '';
                rua['os_icon_big'] = r['icon_big'] || '';
                rua['os_info_url'] = 'https://udger.com/resources/ua-list/os-detail?os=' + (r['name'] || '');
                rua['os_family'] = r['family'] || '';
                rua['os_family_code'] = r['family_code'] || '';
                rua['os_family_vendor'] = r['vendor'] || '';
                rua['os_family_vendor_code'] = r['vendor_code'] || '';
                rua['os_family_vendor_homepage'] = r['vendor_homepage'] || '';

                rua['os'] && dotProp.set(ruaJson, 'os.name', rua['os']);
                rua['os_code'] && dotProp.set(ruaJson, 'os.code', rua['os_code']);
                rua['os_homepage'] && dotProp.set(ruaJson, 'os.homepage', rua['os_homepage']);
                rua['os_icon'] && dotProp.set(ruaJson, 'os.icon', rua['os_icon']);
                rua['os_icon_big'] && dotProp.set(ruaJson, 'os.iconBig', rua['os_icon_big']);
                rua['os_info_url'] && dotProp.set(ruaJson, 'os.infoUrl', rua['os_info_url']);
                rua['os_family'] && dotProp.set(ruaJson, 'os.family.name', rua['os_family']);
                rua['os_family_code'] && dotProp.set(ruaJson, 'os.family.code', rua['os_family_code']);
                rua['os_family_vendor'] && dotProp.set(ruaJson, 'os.family.vendor.name', rua['os_family_vendor']);
                rua['os_family_vendor_code'] && dotProp.set(ruaJson, 'os.family.vendor.code', rua['os_family_vendor_code']);
                rua['os_family_vendor_homepage'] && dotProp.set(ruaJson, 'os.family.vendor.homepage', rua['os_family_vendor_homepage']);

            }
        }

        ////////////////////////////////////////////////
        // device
        ////////////////////////////////////////////////

        q = this.data.udger_deviceclass_regex.columns.regstring;

        for (r of this.data.udger_deviceclass_regex.data) {
            e = ua.match(utils.phpRegexpToJs(r[q]));
            if (e) {

                r = this.map({
                    table: 'udger_deviceclass_regex',
                    row: r,
                    keys: ['deviceclass_id', 'regstring']
                });
                r = {
                    ...r, ...this.map({
                        table: 'udger_deviceclass_list',
                        row: this.data.udger_deviceclass_list.data[r.deviceclass_id],
                        keys: ['id', 'name', 'name_code', 'icon', 'icon_big'],
                        rename: { id: 'deviceclass_id' }
                    })
                }

                debug('parse useragent string: device found by regex');

                deviceclass_id = r['deviceclass_id'];
                rua['device_class'] = r['name'] || '';
                rua['device_class_code'] = r['name_code'] || '';
                rua['device_class_icon'] = r['icon'] || '';
                rua['device_class_icon_big'] = r['icon_big'] || '';
                rua['device_class_info_url'] = 'https://udger.com/resources/ua-list/device-detail?device=' + r['name'];

                if (opts.full) {
                    rua['device_class'] && dotProp.set(ruaJson, 'device.class.name', rua['device_class']);
                    rua['device_class_code'] && dotProp.set(ruaJson, 'device.class.code', rua['device_class_code']);
                    rua['device_class_icon'] && dotProp.set(ruaJson, 'device.class.icon', rua['device_class_icon']);
                    rua['device_class_icon_big'] && dotProp.set(ruaJson, 'device.class.iconBig', rua['device_class_icon_big']);
                    rua['device_class_info_url'] && dotProp.set(ruaJson, 'device.class.infoUrl', rua['device_class_info_url']);
                } else {
                    rua['device_class_code'] && dotProp.set(ruaJson, 'device.class', rua['device_class_code']);
                }

                break;
            }
        }

        if (deviceclass_id == 0 && client_class_id != -1) {
            r = this.findBy('udger_client_class', (row, { id }) => row[id] === client_class_id);

            if (r) {

                r = this.map({
                    table: 'udger_client_class',
                    row: r,
                    keys: ['deviceclass_id']
                });
                r = {
                    ...r, ...this.map({
                        table: 'udger_deviceclass_list',
                        row: this.data.udger_deviceclass_list.data[r.deviceclass_id],
                        keys: ['id', 'name', 'name_code', 'icon', 'icon_big'],
                        rename: { id: 'deviceclass_id' }
                    })
                }

                debug('parse useragent string: device found by deviceclass');

                deviceclass_id = r['deviceclass_id'];
                rua['device_class'] = r['name'] || '';
                rua['device_class_code'] = r['name_code'] || '';
                rua['device_class_icon'] = r['icon'] || '';
                rua['device_class_icon_big'] = r['icon_big'] || '';
                rua['device_class_info_url'] = 'https://udger.com/resources/ua-list/device-detail?device=' + (r['name'] || '');

                if (opts.full) {
                    rua['device_class'] && dotProp.set(ruaJson, 'device.class.name', rua['device_class']);
                    rua['device_class_code'] && dotProp.set(ruaJson, 'device.class.code', rua['device_class_code']);
                    rua['device_class_icon'] && dotProp.set(ruaJson, 'device.class.icon', rua['device_class_icon']);
                    rua['device_class_icon_big'] && dotProp.set(ruaJson, 'device.class.iconBig', rua['device_class_icon_big']);
                    rua['device_class_info_url'] && dotProp.set(ruaJson, 'device.class.infoUrl', rua['device_class_info_url']);
                } else {
                    rua['device_class_code'] && dotProp.set(ruaJson, 'device.class', rua['device_class_code']);
                }
            }
        }

        ////////////////////////////////////////////////
        // device marketname
        ////////////////////////////////////////////////

        if (rua['os_family_code']) {
            let { regstring: regCol, id: idCol } = this.data.udger_devicename_regex.columns;

            q = this.filterBy('udger_devicename_regex', (row, { os_family_code, os_code }) => {
                let condition1 = row[os_family_code] === rua['os_family_code'];
                let condition2 = row[os_code] === '-all-' || row[os_code] === rua['os_code'];
                return condition1 && condition2;
            });

            let match;
            let rId;
            for (const r of q) {
                e = ua.match(utils.phpRegexpToJs(r[regCol]));
                if (e && e[1]) {
                    match = e[1].trim();
                    rId = r[idCol];
                    break;
                }
            }

            let qC = this.findBy('udger_devicename_list', (row, { regex_id, code }) => {
                return row[regex_id] === rId && row[code] === match;
            })

            if (qC) {

                let rC = this.map({
                    table: 'udger_devicename_list',
                    row: qC,
                    keys: ['marketname', 'brand_id']
                });
                rC = {
                    ...rC, ...this.map({
                        table: 'udger_devicename_brand',
                        row: this.data.udger_devicename_brand.data[rC.brand_id],
                        keys: ['id', 'brand_code', 'brand', 'brand_url', 'icon', 'icon_big'],
                        rename: { id: 'brand_id' }
                    })
                };

                debug('parse useragent string: device marketname found');

                rua['device_marketname'] = rC['marketname'] || '';
                rua['device_brand'] = rC['brand'] || '';
                rua['device_brand_code'] = rC['brand_code'] || '';
                rua['device_brand_homepage'] = rC['brand_url'] || '';
                rua['device_brand_icon'] = rC['icon'] || '';
                rua['device_brand_icon_big'] = rC['icon_big'] || '';
                rua['device_brand_info_url'] = 'https://udger.com/resources/ua-list/devices-brand-detail?brand=' + (rC['brand_code'] || '');

                rua['device_marketname'] && dotProp.set(ruaJson, 'device.marketName', rua['device_marketname']);
                rua['device_brand'] && dotProp.set(ruaJson, 'device.brand.name', rua['device_brand']);
                rua['device_brand_code'] && dotProp.set(ruaJson, 'device.brand.code', rua['device_brand_code']);
                rua['device_brand_homepage'] && dotProp.set(ruaJson, 'device.brand.homepage', rua['device_brand_homepage']);
                rua['device_brand_icon'] && dotProp.set(ruaJson, 'device.brand.icon', rua['device_brand_icon']);
                rua['device_brand_icon_big'] && dotProp.set(ruaJson, 'device.brand.iconBig', rua['device_brand_icon_big']);
                rua['device_brand_info_url'] && dotProp.set(ruaJson, 'device.brand.infoUrl', rua['device_brand_info_url']);

            }
        }

        debug('parse useragent string: END, unset useragent string');

        return {
            udger: rua,
            json: ruaJson
        };
    }

    /**
     * Parse the IP Address
     * @param {String} ip - An IPv4 or IPv6 Address
     */
    parseIp(ip, opts) {

        const rip = JSON.parse(JSON.stringify(this.retIp));
        const ripJson = {};

        if (!ip) return {
            udger: rip,
            json: ripJson
        };


        let q;
        let r;
        let ipInt;
        let ipa;

        debug('parse IP address: START (IP: ' + ip + ')');

        rip['ip'] = ip;
        dotProp.set(ripJson, 'ip', ip);

        const ipver = utils.getIpVersion(ip);

        if (ipver === 4 || ipver === 6) {
            if (ipver === 6) {
                ip = utils.inetNtop(utils.inetPton(ip));
                debug('compress IP address is:' + ip);
            }
        }

        rip['ip_ver'] = ipver;
        if (opts.full) {
            dotProp.set(ripJson, 'version', ipver);
        }

        q = this.findBy('udger_ip_list', (row, columns) => row[columns.ip] === ip);

        if (q) {

            r = this.map({
                table: 'udger_ip_list',
                row: q,
                keys: ['class_id', 'crawler_id', 'ip_last_seen', 'ip_hostname', 'ip_country', 'ip_city', 'ip_country_code'],
            });
            r = {
                ...r, ...this.map({
                    table: 'udger_ip_class',
                    row: this.data.udger_ip_class.data[r.class_id], // `class_id` of udger_ip_list
                    keys: ['ip_classification', 'ip_classification_code']
                })
            }
            delete r.class_id; // Remove `class_id` field taken from udger_ip_list
            r = {
                ...r, ...this.map({
                    table: 'udger_crawler_list',
                    row: this.data.udger_crawler_list.data[r.crawler_id],
                    keys: [
                        'id', 'name', 'ver', 'ver_major', 'class_id', 'last_seen',
                        'respect_robotstxt', 'family', 'family_code', 'family_homepage',
                        'family_icon', 'vendor', 'vendor_code', 'vendor_homepage'
                    ],
                    rename: { id: 'botid' }
                })
            }
            delete r.crawler_id; // Remove `crawler_id` field taken from udger_ip_list
            r = { ...r, ...this.map({
                table: 'udger_crawler_class',
                row: this.data.udger_crawler_class.data[r.class_id], // `class_id` of udger_crawler_list
                keys: ['crawler_classification', 'crawler_classification_code']
            })};
            delete r.class_id; // Remove `class_id` field taken from udger_crawler_list

            // UDGER FORMAT
            rip['ip_classification'] = r['ip_classification'] || '';
            rip['ip_classification_code'] = r['ip_classification_code'] || '';
            rip['ip_last_seen'] = r['ip_last_seen'] || '';
            rip['ip_hostname'] = r['ip_hostname'] || '';
            rip['ip_country'] = r['ip_country'] || '';
            rip['ip_country_code'] = r['ip_country_code'] || '';
            rip['ip_city'] = r['ip_city'] || '';

            rip['crawler_name'] = r['name'] || '';
            rip['crawler_ver'] = r['ver'] || '';
            rip['crawler_ver_major'] = r['ver_major'] || '';
            rip['crawler_family'] = r['family'] || '';
            rip['crawler_family_code'] = r['family_code'] || '';
            rip['crawler_family_homepage'] = r['family_homepage'] || '';
            rip['crawler_family_vendor'] = r['vendor'] || '';
            rip['crawler_family_vendor_code'] = r['vendor_code'] || '';
            rip['crawler_family_vendor_homepage'] = r['vendor_homepage'] || '';
            rip['crawler_family_icon'] = r['family_icon'] || '';
            if (r['ip_classification_code'] === 'crawler') {
                rip['crawler_family_info_url'] = 'https://udger.com/resources/ua-list/bot-detail?bot=' + (r['family'] || '') + '#id' + (r['botid'] || '');
            }
            rip['crawler_last_seen'] = r['last_seen'] || '';
            rip['crawler_category'] = r['crawler_classification'] || '';
            rip['crawler_category_code'] = r['crawler_classification_code'] || '';
            rip['crawler_respect_robotstxt'] = r['respect_robotstxt'] || '';

            // JSON FORMAT
            if (opts.full) {
                rip['ip_classification'] && dotProp.set(ripJson, 'classification.name', rip['ip_classification']);
                rip['ip_classification_code'] && dotProp.set(ripJson, 'classification.code', rip['ip_classification_code']);
            } else {
                rip['ip_classification_code'] && dotProp.set(ripJson, 'classification', rip['ip_classification_code']);
            }

            rip['ip_last_seen'] && dotProp.set(ripJson, 'lastSeen', rip['ip_last_seen']);
            rip['ip_hostname'] && dotProp.set(ripJson, 'hostname', rip['ip_hostname']);
            rip['ip_country'] && dotProp.set(ripJson, 'geo.country.name', rip['ip_country']);
            rip['ip_country_code'] && dotProp.set(ripJson, 'geo.country.code', rip['ip_country_code']);
            rip['ip_city'] && dotProp.set(ripJson, 'geo.city', rip['ip_city']);

            rip['crawler_name'] && dotProp.set(ripJson, 'crawler.name', rip['crawler_name']);
            if (opts.full) {
                rip['crawler_ver'] && dotProp.set(ripJson, 'crawler.version.current', rip['crawler_ver']);
                rip['crawler_ver_major'] && dotProp.set(ripJson, 'crawler.version.major', rip['crawler_ver_major']);
                rip['crawler_family'] && dotProp.set(ripJson, 'crawler.family.name', rip['crawler_family']);
                rip['crawler_family_code'] && dotProp.set(ripJson, 'crawler.family.code', rip['crawler_family_code']);
                rip['crawler_family_homepage'] && dotProp.set(ripJson, 'crawler.family.homepage', rip['crawler_family_homepage']);
                rip['crawler_family_vendor'] && dotProp.set(ripJson, 'crawler.family.vendor.name', rip['crawler_family_vendor']);
                rip['crawler_family_vendor_code'] && dotProp.set(ripJson, 'crawler.family.vendor.code', rip['crawler_family_vendor_code']);
                rip['crawler_family_vendor_homepage'] && dotProp.set(ripJson, 'crawler.family.vendor.homepage', rip['crawler_family_vendor_homepage']);
                rip['crawler_family_icon'] && dotProp.set(ripJson, 'crawler.family.icon', rip['crawler_family_icon']);
                if (r['ip_classification_code'] === 'crawler') {
                    rip['crawler_family_info_url'] && dotProp.set(ripJson, 'crawler.family.infoUrl', rip['crawler_family_info_url']);
                }
                rip['crawler_last_seen'] && dotProp.set(ripJson, 'crawler.lastSeen', rip['crawler_last_seen']);
                rip['crawler_category'] && dotProp.set(ripJson, 'crawler.category.name', rip['crawler_category']);
                rip['crawler_category_code'] && dotProp.set(ripJson, 'crawler.category.code', rip['crawler_category_code']);
                rip['crawler_respect_robotstxt'] && dotProp.set(ripJson, 'crawler.respectRobotsTxt', rip['crawler_category_code']);
            } else {
                rip['crawler_family_code'] && dotProp.set(ripJson, 'crawler.family', rip['crawler_family_code']);
                rip['crawler_category_code'] && dotProp.set(ripJson, 'crawler.category', rip['crawler_category_code']);
                rip['crawler_last_seen'] && dotProp.set(ripJson, 'crawler.lastSeen', rip['crawler_last_seen']);
            }

        } else {

            rip['ip_classification'] = 'Unrecognized';
            rip['ip_classification_code'] = 'unrecognized';

            if (opts.full) {
                dotProp.set(ripJson, 'classification.name', rip['ip_classification']);
                dotProp.set(ripJson, 'classification.code', rip['ip_classification_code']);
            } else {
                dotProp.set(ripJson, 'classification', rip['ip_classification_code']);
            }
        }

        if (ipver === 4) {

            ipInt = utils.ip2long(ip);

            q = this.findBy('udger_datacenter_range', (row, {iplong_from, iplong_to}) => {
                return row[iplong_from] <= ipInt && row[iplong_to] >= ipInt;
            })

            if (q) {

                r = this.map({
                    table: 'udger_datacenter_range',
                    row: q,
                    keys: ['datacenter_id']
                });
                r = {...r, ...this.map({
                    table: 'udger_datacenter_list',
                    row: this.data.udger_datacenter_list.data[r.datacenter_id],
                    keys: ['name', 'name_code', 'homepage']
                })};
                delete r.datacenter_id;

                rip['datacenter_name'] = r['name'] || '';
                rip['datacenter_name_code'] = r['name_code'] || '';
                rip['datacenter_homepage'] = r['homepage'] || '';

                if (opts.full) {
                    rip['datacenter_name'] && dotProp.set(ripJson, 'datacenter.name', rip['datacenter_name']);
                    rip['datacenter_name_code'] && dotProp.set(ripJson, 'datacenter.code', rip['datacenter_name_code']);
                    rip['datacenter_homepage'] && dotProp.set(ripJson, 'datacenter.homepage', rip['datacenter_homepage']);
                } else {
                    rip['datacenter_name_code'] && dotProp.set(ripJson, 'datacenter', rip['datacenter_name_code']);
                }

            }

        } else if (ipver === 6) {

            ipa = new Address6(ip);
            const t = ipa.canonicalForm().split(':');
            const ipInts = {};
            t.forEach((h, i) => {
                ipInts['ipInt' + i] = parseInt(h, 16);
            });

            q = this.findBy('udger_datacenter_range6', (row, columns) => {
                let ret =
                row[columns.iplong_from0] <= ipInts.ipInt0 && row[columns.iplong_to0] >= ipInts.ipInt0 &&
                row[columns.iplong_from1] <= ipInts.ipInt1 && row[columns.iplong_to1] >= ipInts.ipInt1 &&
                row[columns.iplong_from2] <= ipInts.ipInt2 && row[columns.iplong_to2] >= ipInts.ipInt2 &&
                row[columns.iplong_from3] <= ipInts.ipInt3 && row[columns.iplong_to3] >= ipInts.ipInt3 &&
                row[columns.iplong_from4] <= ipInts.ipInt4 && row[columns.iplong_to4] >= ipInts.ipInt4 &&
                row[columns.iplong_from5] <= ipInts.ipInt5 && row[columns.iplong_to5] >= ipInts.ipInt5 &&
                row[columns.iplong_from6] <= ipInts.ipInt6 && row[columns.iplong_to6] >= ipInts.ipInt6 &&
                row[columns.iplong_from7] <= ipInts.ipInt7 && row[columns.iplong_to7] >= ipInts.ipInt7;
                return ret;
            })

            if (q) {

                r = this.map({
                    table: 'udger_datacenter_range6',
                    row: q,
                    keys: ['datacenter_id']
                });
                r = {...r, ...this.map({
                    table: 'udger_datacenter_list',
                    row: this.data.udger_datacenter_list.data[r.datacenter_id],
                    keys: ['name', 'name_code', 'homepage']
                })};
                delete r.datacenter_id;

                rip['datacenter_name'] = r['name'] || '';
                rip['datacenter_name_code'] = r['name_code'] || '';
                rip['datacenter_homepage'] = r['homepage'] || '';

                if (opts.full) {
                    rip['datacenter_name'] && dotProp.set(ripJson, 'datacenter.name', rip['datacenter_name']);
                    rip['datacenter_name_code'] && dotProp.set(ripJson, 'datacenter.code', rip['datacenter_name_code']);
                    rip['datacenter_homepage'] && dotProp.set(ripJson, 'datacenter.homepage', rip['datacenter_homepage']);
                } else {
                    rip['datacenter_name_code'] && dotProp.set(ripJson, 'datacenter', rip['datacenter_name_code']);
                }
            }

        }

        debug('parse IP address: END');

        return {
            udger: rip,
            json: ripJson
        };
    }

    /**
     * Main parser
     * @return {Object} Parsing result
     */
    parse(opts) {

        if (!this.db) return {};

        if (
            this.isCacheEnable() &&
            this.cacheKeyExist(this.keyCache)
        ) {
            return this.cacheRead(this.keyCache, opts);
        }

        const ret = {};
        if (!opts) opts = {};

        if (opts.json) {
            if (this.ua) ret.userAgent = this.parseUa(this.ua, opts).json;
            if (this.ip) ret.ipAddress = this.parseIp(this.ip, opts).json;
            if (opts.full) ret.fromCache = false;
        } else {
            ret['user_agent'] = this.parseUa(this.ua, opts).udger;
            ret['ip_address'] = this.parseIp(this.ip, opts).udger;
            ret['from_cache'] = false;
        }

        if (this.isCacheEnable()) {
            this.cacheWrite(this.keyCache, ret);
        }

        return ret;
    }

    randomSanityChecks(max, callback) {
        if (!this.db) {
            callback(new Error('Database not ready'));
            return false;
        }

        if (!max) {
            callback(new Error('Please specify maximum number of records'));
            return false;
        }

        if (typeof max != 'number') {
            callback(new Error('Maximum number of records is not a number'));
            return false;
        }

        return true;
    }

    randomUACrawlers(max, callback) {

        if (!this.randomSanityChecks(max, callback)) return;

        const q = this.db.prepare(
            'SELECT ua_string FROM udger_crawler_list ORDER BY RANDOM() LIMIT ?'
        );

        callback(null, q.all(max));
        return;
    }

    randomUAClientsRegex(max, callback) {
        if (!this.randomSanityChecks(max, callback)) return;

        const q = this.db.prepare(
            'SELECT regstring FROM udger_client_regex ORDER BY RANDOM() LIMIT ?'
        );

        callback(null, q.all(max));
        return;
    }

    randomUAClients(max, callback) {

        if (!this.randomSanityChecks(max, callback)) return;
        this.randomUAClientsRegex(max, (err, results) => {
            let regex;
            let regexClean;
            let randomUA;
            let re;
            let reClean;
            for (let i = 0, len = results.length; i < len; i++) {
                regex = new RegExp(results[i].regstring);
                regexClean = results[i].regstring.replace(/^\//, '');
                regexClean = regexClean.replace(/\/si$/, '');
                reClean = new RegExp(regexClean);
                re = new RandExp(reClean);

                re.max = 5;                         // limit random for * and +
                re.defaultRange.subtract(32, 126);  // remove defaults random chars
                re.defaultRange.add(43, 43);        // add +
                re.defaultRange.add(45, 46);        // add . and -
                re.defaultRange.add(48, 57);        // add 0-9
                re.defaultRange.add(97, 122);       // add a-z
                re.defaultRange.add(65, 90);        // add A-Z

                randomUA = re.gen();

                results[i].randomUA = randomUA;

                /*
                if (!randomUA.match(reClean)) {
                    console.log('original',results[i].regstring);
                    console.log('clean',regexClean);
                    console.log('ua',ua);
                    console.log('result',randomUA.match(new RegExp(regexClean)));
                }
                */
            }

            callback(null, results);
        });
    }

    randomIPv4(max, callback) {
        if (!this.randomSanityChecks(max, callback)) return;

        const q = this.db.prepare(
            'SELECT ip FROM udger_ip_list WHERE ip LIKE \'%.%.%.%\' ORDER BY RANDOM() LIMIT ?'
        );

        callback(null, q.all(max));
        return;
    }

    getUAClientsClassification(callback) {
        if (!this.db) {
            callback(new Error('Database not ready'));
            return false;
        }

        const q = this.db.prepare(
            'SELECT client_classification, client_classification_code FROM udger_client_class'
        );

        callback(null, q.all());
        return;
    }

    getUACrawlersClassification(callback) {
        if (!this.db) {
            callback(new Error('Database not ready'));
            return false;
        }

        const q = this.db.prepare(
            'SELECT crawler_classification, crawler_classification_code FROM udger_crawler_class'
        );

        callback(null, q.all());
        return;
    }

    getUACrawlersFamilies(callback) {
        if (!this.db) {
            callback(new Error('Database not ready'));
            return false;
        }

        const q = this.db.prepare(
            'SELECT DISTINCT ' +
            'udger_crawler_list.family_code,' +
            'udger_crawler_class.crawler_classification_code ' +
            'FROM udger_crawler_list ' +
            'LEFT JOIN udger_crawler_class ON udger_crawler_class.id=udger_crawler_list.class_id ' +
            'WHERE family_code != "" ' +
            'ORDER BY family_code, crawler_classification_code'
        );

        callback(null, q.all());
        return;
    }

    getDatabaseInfo(callback) {
        if (!this.db) {
            callback(new Error('Database not ready'));
            return false;
        }

        const q = this.db.prepare(
            'SELECT * FROM udger_db_info'
        );

        const result = q.get();
        delete result.key;

        callback(null, result);
        return;
    }

    getIPsClassification(callback) {
        if (!this.db) {
            callback(new Error('Database not ready'));
            return false;
        }

        const q = this.db.prepare(
            'SELECT ip_classification, ip_classification_code FROM udger_ip_class'
        );

        callback(null, q.all());
        return;
    }
}

module.exports = function (file) {
    return new (UdgerParser)(file);
};
