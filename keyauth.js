const uuid = require('uuid').v4;
const { createHash, createCipheriv, createDecipheriv } = require('crypto');
const axios = require('axios');
const { execSync } = require('child_process');
const os = require('os');

class keyauth {
    constructor (name, ownerid, secret, version, hash_to_check) {
        if(!(name && ownerid && secret && version && hash_to_check) ) {
            console.log('Make sure you fill out all fields')
            process.exit(1)
        }

        this.name = name

        this.ownerid = ownerid
    
        this.secret = secret

        this.version = version
        this.hash_to_check = hash_to_check
    };

    initialize = () => new Promise(async(resolve) => {
        this.enckey = createHash('sha256').update(uuid().substring(0, 8)).digest('hex');
        const init_iv = createHash('sha256').update(uuid().substring(0, 8)).digest('hex');

        const post_data = {
            'type': Buffer.from('init').toString('hex'),
            'ver': Encryption.encrypt(this.version, this.secret, init_iv),
            'hash': this.hash_to_check,
            'enckey': Encryption.encrypt(this.enckey, this.secret, init_iv),
            'name': Buffer.from(this.name).toString('hex'),
            'ownerid': Buffer.from(this.ownerid).toString('hex'),
            'init_iv': init_iv
        }

        const response = await make_request(post_data)
        const decrypted = Encryption.decrypt(response, this.secret, init_iv)

        const parsed = JSON.parse(decrypted)

        if(!parsed.success || parsed.success == false){
            return resolve(false)
        }

        this.sessionid = parsed.sessionid
        this.initialized = true
        
        resolve(parsed)
    });

    register = (user, password, license, hwid = null) => new Promise(async(resolve) => {
        this.check_initialize()

        if(!hwid) {
            hwid = Misc.get_hwid()
        }

        const init_iv = createHash('sha256').update(uuid().substring(0, 8)).digest('hex');

        const post_data = {
            'type': Buffer.from('register').toString('hex'),
            'username': Encryption.encrypt(user, this.enckey, init_iv),
            'pass': Encryption.encrypt(password, this.enckey, init_iv),
            'key': Encryption.encrypt(license, this.enckey, init_iv),
            'hwid': Encryption.encrypt(hwid, this.enckey, init_iv),
            'sessionid': Buffer.from(this.sessionid).toString('hex'),
            'name': Buffer.from(this.name).toString('hex'),
            'ownerid': Buffer.from(this.ownerid).toString('hex'),
            'init_iv': init_iv
        }

        const response = await make_request(post_data)
        const decrypted = Encryption.decrypt(response, this.enckey, init_iv)

        const parsed = JSON.parse(decrypted)

        if(!parsed.success || parsed.success == false){
            return resolve(parsed.message)
        }else{
            resolve(parsed)
        }
    })

    upgrade = (username, license) => new Promise(async(resolve) => {
        this.check_initialize()

        const init_iv = createHash('sha256').update(uuid().substring(0, 8)).digest('hex');

        const post_data = {
            'type': Buffer.from('upgrade').toString('hex'),
            'username': Encryption.encrypt(username, this.enckey, init_iv),
            'key': Encryption.encrypt(license, this.enckey, init_iv),
            'sessionid': Buffer.from(this.sessionid).toString('hex'),
            'name': Buffer.from(this.name).toString('hex'),
            'ownerid': Buffer.from(this.ownerid).toString('hex'),
            'init_iv': init_iv
        }

        const response = await make_request(post_data)
        const decrypted = Encryption.decrypt(response, this.enckey, init_iv)

        const parsed = JSON.parse(decrypted)

        if(!parsed.success || parsed.success == false){
            return resolve(parsed.message)
        }else{
            resolve(parsed)
        }
    })

    login = (username, password, hwid = null) => new Promise(async(resolve) => {
        this.check_initialize()

        if(!hwid) {
            hwid = Misc.get_hwid()
        }

        const init_iv = createHash('sha256').update(uuid().substring(0, 8)).digest('hex');

        const post_data = {
            'type': Buffer.from('login').toString('hex'),
            'username': Encryption.encrypt(username, this.enckey, init_iv),
            'pass': Encryption.encrypt(password, this.enckey, init_iv),
            'hwid': Encryption.encrypt(hwid, this.enckey, init_iv),
            'sessionid': Buffer.from(this.sessionid).toString('hex'),
            'name': Buffer.from(this.name).toString('hex'),
            'ownerid': Buffer.from(this.ownerid).toString('hex'),
            'init_iv': init_iv
        }

        const response = await make_request(post_data)
        const decrypted = Encryption.decrypt(response, this.enckey, init_iv)

        const parsed = JSON.parse(decrypted)

        if(parsed.success && parsed.success == true) {
            return resolve(parsed)
        }

        resolve(parsed.data)
    })

    license = (key, hwid = null) => new Promise(async(resolve) => {
        this.check_initialize()

        if(hwid == null) {
            hwid = Misc.get_hwid()
        }

        const init_iv = createHash('sha256').update(uuid().substring(0, 8)).digest('hex');

        const post_data = {
            'type': Buffer.from('license').toString('hex'),
            'key': Encryption.encrypt(key, this.enckey, init_iv),
            'hwid': Encryption.encrypt(hwid, this.enckey, init_iv),
            'sessionid': Buffer.from(this.sessionid).toString('hex'),
            'name': Buffer.from(this.name).toString('hex'),
            'ownerid': Buffer.from(this.ownerid).toString('hex'),
            'init_iv': init_iv
        }

        const response = await make_request(post_data)
        const decrypted = Encryption.decrypt(response, this.enckey, init_iv)

        const parsed = JSON.parse(decrypted)

        if(parsed.success && parsed.success == true) {
            return resolve(parsed)
        }

        resolve(parsed.message)
    });

    var = (variable_name) => new Promise(async(resolve) => {
        this.check_initialize()

        const init_iv = createHash('sha256').update(uuid().substring(0, 8)).digest('hex');

        const post_data = {
            'type': Buffer.from('var').toString('hex'),
            'varid': Encryption.encrypt(variable_name, this.enckey, init_iv),
            'sessionid': Buffer.from(this.sessionid).toString('hex'),
            'name': Buffer.from(this.name).toString('hex'),
            'ownerid': Buffer.from(this.ownerid).toString('hex'),
            'init_iv': init_iv
        }

        const response = await make_request(post_data)
        const decrypted = Encryption.decrypt(response, this.enckey, init_iv)

        const parsed = JSON.parse(decrypted)

        
        if(parsed.success && parsed.success == true) {
            return resolve(parsed)
        }

        resolve(parsed.message)
    })

    getvar = (variable_name) => new Promise(async(resolve) => {
        this.check_initialize()

        const init_iv = createHash('sha256').update(uuid().substring(0, 8)).digest('hex');

        const post_data = {
            'type': Buffer.from('getvar').toString('hex'),
            'var': Encryption.encrypt(variable_name, this.enckey, init_iv),
            'sessionid': Buffer.from(this.sessionid).toString('hex'),
            'name': Buffer.from(this.name).toString('hex'),
            'ownerid': Buffer.from(this.ownerid).toString('hex'),
            'init_iv': init_iv
        }

        const response = await make_request(post_data)
        const decrypted = Encryption.decrypt(response, this.enckey, init_iv)

        const parsed = JSON.parse(decrypted)

        if(parsed.success && parsed.success == true) {
            return resolve(parsed)
        }

        resolve(parsed.message)
    })

    setvar = (variable_name, variable_data) => new Promise(async(resolve) => {
        this.check_initialize()

        const init_iv = createHash('sha256').update(uuid().substring(0, 8)).digest('hex');

        const post_data = {
            'type': Buffer.from('setvar').toString('hex'),
            'var': Encryption.encrypt(variable_name, this.enckey, init_iv),
            'data': Encryption.encrypt(variable_data, this.enckey, init_iv),
            'sessionid': Buffer.from(this.sessionid).toString('hex'),
            'name': Buffer.from(this.name).toString('hex'),
            'ownerid': Buffer.from(this.ownerid).toString('hex'),
            'init_iv': init_iv
        }

        const response = await make_request(post_data)
        const decrypted = Encryption.decrypt(response, this.enckey, init_iv)

        const parsed = JSON.parse(decrypted)

        if(parsed.success && parsed.success == true) {
            return resolve(parsed)
        }

        resolve(parsed.message)
    })

    ban = () => new Promise(async(resolve) => {
        this.check_initialize()

        const init_iv = createHash('sha256').update(uuid().substring(0, 8)).digest('hex');

        const post_data = {
            'type': Buffer.from('ban').toString('hex'),
            'sessionid': Buffer.from(this.sessionid).toString('hex'),
            'name': Buffer.from(this.name).toString('hex'),
            'ownerid': Buffer.from(this.ownerid).toString('hex'),
            'init_iv': init_iv
        }

        const response = await make_request(post_data)
        const decrypted = Encryption.decrypt(response, this.enckey, init_iv)

        const parsed = JSON.parse(decrypted)

        if(parsed.success && parsed.success == true) {
            return resolve(true)
        }

        resolve(parsed.message)
    })

    file = (fileid) => new Promise(async(resolve) => {
        this.check_initialize()

        const init_iv = createHash('sha256').update(uuid().substring(0, 8)).digest('hex');

        const post_data = {
            'type': Buffer.from('file').toString('hex'),
            'fileid': Encryption.encrypt(fileid.toString(), this.enckey, init_iv),
            'sessionid': Buffer.from(this.sessionid).toString('hex'),
            'name': Buffer.from(this.name).toString('hex'),
            'ownerid': Buffer.from(this.ownerid).toString('hex'),
            'init_iv': init_iv
        }

        const response = await make_request(post_data)
        const decrypted = Encryption.decrypt(response, this.enckey, init_iv)

        const parsed = JSON.parse(decrypted)

        if(parsed.success && parsed.success == true) {
            return resolve(Buffer.from(parsed.contents, 'hex').toString('utf-8'))
        }

        resolve(parsed.message)
    })

    webhook = (webid, param) => new Promise(async(resolve) => { //havent tested
        this.check_initialize()

        const init_iv = createHash('sha256').update(uuid().substring(0, 8)).digest('hex');

        const post_data = {
            'type': Buffer.from('webhook').toString('hex'),
            'webid': Encryption.encrypt(webid, this.enckey, init_iv),
            'params': Encryption.encrypt(param, this.enckey, init_iv),
            'sessionid': Buffer.from(this.sessionid).toString('hex'),
            'name': Buffer.from(this.name).toString('hex'),
            'ownerid': Buffer.from(this.ownerid).toString('hex'),
            'init_iv': init_iv
        }

        const response = await make_request(post_data)
        const decrypted = Encryption.decrypt(response, this.enckey, init_iv)

        const parsed = JSON.parse(decrypted)

        if(parsed.success && parsed.success == true) {
            return resolve(parsed)
        }

        resolve(parsed.message)
    })

    check = () => new Promise(async(resolve) => {
        this.check_initialize()

        const init_iv = createHash('sha256').update(uuid().substring(0, 8)).digest('hex');

        const post_data = {
            'type': Buffer.from('check').toString('hex'),
            'sessionid': Buffer.from(this.sessionid).toString('hex'),
            'name': Buffer.from(this.name).toString('hex'),
            'ownerid': Buffer.from(this.ownerid).toString('hex'),
            'init_iv': init_iv
        }

        const response = await make_request(post_data)
        const decrypted = Encryption.decrypt(response, this.enckey, init_iv)

        const parsed = JSON.parse(decrypted)

        if(parsed.success && parsed.success == true) {
            return resolve(parsed)
        }

        resolve(parsed.message)
    })

    check_blacklist = () => new Promise(async(resolve) => {
        this.check_initialize()

        const hwid = Misc.get_hwid()
        const init_iv = createHash('sha256').update(uuid().substring(0, 8)).digest('hex');

        const post_data = {
            'type': Buffer.from('checkblacklist').toString('hex'),
            'hwid': Encryption.encrypt(hwid, this.enckey, init_iv),
            'sessionid': Buffer.from(this.sessionid).toString('hex'),
            'name': Buffer.from(this.name).toString('hex'),
            'ownerid': Buffer.from(this.ownerid).toString('hex'),
            'init_iv': init_iv
        }

        const response = await make_request(post_data)  
        const decrypted = Encryption.decrypt(response, this.enckey, init_iv)

        const parsed = JSON.parse(decrypted)

        if(parsed.success && parsed.success == true) {
            return resolve(true)
        }

        resolve(false) //they arent blacklisted
    });

    log = (message) => new Promise(async(resolve) => {
        this.check_initialize()

        const init_iv = createHash('sha256').update(uuid().substring(0, 8)).digest('hex');

        const post_data = {
            'type': Buffer.from('log').toString('hex'),
            'pcuser': Encryption.encrypt(os.userInfo().username, this.enckey, init_iv),
            'message': Encryption.encrypt(message, this.enckey, init_iv),
            'sessionid': Buffer.from(this.sessionid).toString('hex'),
            'name': Buffer.from(this.name).toString('hex'),
            'ownerid': Buffer.from(this.ownerid).toString('hex'),
            'init_iv': init_iv
        }

        await make_request(post_data)

        resolve(true)
    })

    check_initialize() {
        if(!this.initialized) {
            console.log('Not initialize')
            return process.exit(1)
        }

        return true
    };
}

class Encryption {
    static encrypt(message, enc_key, iv) {
        try{
            const _key = createHash('sha256').update(enc_key).digest('hex').substring(0, 32)
    
            const _iv = createHash('sha256').update(iv).digest('hex').substring(0, 16)
    
            return this.encrypt_string(message, _key, _iv)
        }catch(err){
            console.log(err)
            console.log('Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username')
            process.exit(1)
        }
    };

    static encrypt_string(plain_text, key, iv) {
        const cipher = createCipheriv('aes-256-cbc', key, iv)
        let crypted = cipher.update(plain_text, 'utf-8', 'hex')
        crypted += cipher.final('hex')
        return crypted
    };

    static decrypt(message, key, iv) {
        try{
            const _key = createHash('sha256').update(key).digest('hex').substring(0, 32)
    
            const _iv = createHash('sha256').update(iv).digest('hex').substring(0, 16)
    
            return this.decrypt_string(message, _key, _iv)
        }catch(err) {
            console.log(err)

            console.log('Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username')
            process.exit(1)
        }
    };

    static decrypt_string(cipher_text, key, iv) {
        const decipher = createDecipheriv('aes-256-cbc', key, iv)
        let decrypted = decipher.update(cipher_text, 'hex', 'utf-8')
        decrypted += decipher.final('utf-8')
        return decrypted
    }
}


class Misc {
    static get_hwid() {
        if(os.platform() != 'win32') return false

        const cmd = execSync('wmic useraccount where name="%username%" get sid').toString('utf-8')

        const system_id = cmd.split('\n')[1].trim()
        return system_id
    };
}

async function make_request(data) {
    return new Promise(async(resolve) => {
        const request = await axios({
            method: 'POST', 
            url: 'https://keyauth.win/api/1.0/',
            data: new URLSearchParams(data).toString()
        }).catch((err) => {
            console.log(err)
        })

        if(request && request.data) {
            resolve(request.data)
        }else{
            resolve(null)
        }
    })
}

module.exports = keyauth