<div id="top"></div>

<div align="center">
  <a href="https://automized.sellix.io">
    <img src="https://i.imgur.com/e2y6bnl.png" alt="Logo" width="120" height="120">
  </a>
  
  <h2 align="center">Keyauth Nodejs Version 1.0</h3>

  <p align="center">
    Keyauth version 1.0 that includes and demo and requests are encrypted using aes.
    <br />
    <br />
    <a href="https://discord.gg/ptools">Discord Server</a>
    .
    <a href="https://keyauth.win">Keyauth</a>
    .
    <a href="https://automized.sellix.io">Store</a>
  </p>
</div>

### Requirements

-   A brain
-   Nodejs installed (https://nodejs.org)

<br />
<br />
<br />
<br />
<img src="https://i.imgur.com/m7LEEA5.png" alt="Logo">

### Example

```js
const Keyauth = require('keyauth');
const path = require('path');
const fs = require('fs');
const { createHash } = require('crypto');

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
    const keyauth = new Keyauth(
        '', //application name
        '', //owner id
        '', //application secret
        '1.0', //version
        check_sum()
    );
    
    const app_info = await keyauth.initialize()

    console.log(app_info)
})()

```
