# saml2json

Extracts a base64 encoded SAML 2.0 assertion's attributes into a JSON object.

[![NPM version](https://img.shields.io/npm/v/saml2json.svg)](https://www.npmjs.com/package/saml2json.svg) [![Dependencies](https://img.shields.io/david/flesch/saml2json.svg)](https://david-dm.org/flesch/saml2json.svg) [![Dev-dependencies](https://img.shields.io/david/dev/flesch/saml2json.svg)](https://david-dm.org/flesch/saml2json.svg#info=devDependencies) [![Known Vulnerabilities](https://snyk.io/test/npm/saml2json/badge.svg)](https://snyk.io/test/npm/node-lambda-babel-template)

## Install

```bash
$ npm install --save saml2json
```

## Usage

Assuming the SAML `AttributeStatement` looks like this:

```xml
<saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <saml:Attribute Name="NAME" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
    <saml:AttributeValue xsi:type="xs:string">John Flesch</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="EMAIL" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
    <saml:AttributeValue xsi:type="xs:string">john@fles.ch</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>
```

Parsing with `saml2json.parse([base64stringSAMLassertion])`:

```javascript
const saml2json = require('saml2json');
const attributes = saml2json.parse('PHNhbWw6QXNzZXJ0aW9uIHhtbG5zOnNhbWw9InVy...');
```

Results in an object like this:

```javascript
{
  NAME: 'John Flesch',
  EMAIL: 'john@fles.ch'
}
```

**Note**: `v1.0.0` introduces a breaking change in that the object's keys are unaltered from the SAML attribute names. `v0.0.1` converted the keys to lowercase.

## License

[The MIT License (MIT)](http://flesch.mit-license.org/)

Copyright © 2016 John Flesch, http://fles.ch

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

