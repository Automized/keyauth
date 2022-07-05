const Keyauth = require('./keyauth');
const path = require('path');
const fs = require('fs');
const { createHash } = require('crypto');
const r = require('readline-sync');
const chalk = require('chalk');

function check_sum() {
    let filename = path.basename(__filename) 

    if(!fs.existsSync(filename)) {
        filename = filename.replace(path.extname(filename), '.exe')
    }

    const content = fs.readFileSync(filename, 'binary')
    
    const md5 = createHash('md5').update(content).digest('hex')
    return md5
}

(async() => {
    process.stdout.write(String.fromCharCode(27) + ']0;' + 'Keyauth v1 Example | Follow @Automized on github' + String.fromCharCode(7));
    console.clear()

    const keyauth = new Keyauth(
        '', //application name
        '', //owner id
        '', //application secret
        '1.0', //version
        check_sum()
    );
    
    const app_info = await keyauth.initialize()

    const str = `
    
                █▄▀ █▀▀ █▄█ ▄▀█ █░█ ▀█▀ █░█
                █░█ ██▄ ░█░ █▀█ █▄█ ░█░ █▀█
    ___________________________________________________\n
                [Session ID]: ${app_info.sessionid}
                [Keys]:       ${app_info.appinfo.numKeys}
                [Users]:      ${app_info.appinfo.numUsers}
    ___________________________________________________

    [1] Register                      [6] Set variable
    [2] Login (Username & Password)   [7] Get File
    [3] Upgrade                       [8] Log
    [4] Login (License Key)             
    [5] Get Global Variable           Developer: github.com/Automized\n`
    .replace(/\[/g, chalk.cyanBright('['))
    .replace(/]/g, chalk.cyanBright(']'))      
    .replace('github.com/Automized', chalk.cyanBright('github.com/Automized')) 
    .replace(/█/g, chalk.cyanBright('█'))
    .replace(/▀/g, chalk.cyanBright('▀'))
    .replace(/▄/g, chalk.cyanBright('▄'))

    console.log(str)
    const option = r.question(chalk.cyanBright('    > '))
    console.log()

    if(option == '1') {
        const username = r.question(chalk.cyanBright('    Username: '))
        const password = r.question(chalk.cyanBright('    Password: '))
        const license_key = r.question(chalk.cyanBright('    License Key: '))

        console.log()

        const req = await keyauth.register(username, password, license_key)
        console.log(chalk.cyanBright('    Keyauth Response:'), req)
        r.question()
    }else if(option == '2') {
        const username = r.question(chalk.cyanBright('    Username: '))
        const password = r.question(chalk.cyanBright('    Password: '))

        const req = await keyauth.login(username, password)
        console.log(chalk.cyanBright('    Keyauth Response:'), req)
        r.question()
    }else if(option == '3') {
        const username = r.question(chalk.cyanBright('    Username: '))
        const license_key = r.question(chalk.cyanBright('    License Key: '))

        const req = await keyauth.upgrade(username, license_key)
        console.log(chalk.cyanBright('    Keyauth Response:'), req)
        r.question()
    }else if(option == '4') {
        const license_key = r.question(chalk.cyanBright('    License Key: '))

        const req = await keyauth.license(license_key)
        console.log(chalk.cyanBright('    Keyauth Response:'), req)
        r.question()
    }else if(option == '5') {
        const var_name = r.question(chalk.cyanBright('    Variable Name: '))

        const req = await keyauth.var(var_name)
        console.log(chalk.cyanBright('    Keyauth Response:'), req)
        r.question()
    }else if(option == '6') {
        const var_name = r.question(chalk.cyanBright('    Variable Name: '))
        const var_data = r.question(chalk.cyanBright('    Variable Data: '))

        const req = await keyauth.setvar(var_name, var_data)
        console.log(chalk.cyanBright('    Keyauth Response:'), req)
        r.question()
    }else if(option == '7') {
        const fileid = r.question(chalk.cyanBright('    File ID: '))

        const req = await keyauth.file(fileid)
        console.log(chalk.cyanBright('    Keyauth Response:'), req)
        r.question()
    }else if(option == '8') {
        const log_message = r.question(chalk.cyanBright('    Message: '))

        const req = await keyauth.log(log_message)
        console.log(chalk.cyanBright('    Keyauth Response:'), req)
        r.question()
    }else{
        console.log(chalk.cyanBright('    Invalid Choice'))
        r.question()
    }
})()