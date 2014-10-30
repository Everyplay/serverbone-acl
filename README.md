serverbone-acl
==============

Simple inline RBAC for Serverbone

Usage:

```js
var ACL = require('serverbone-acl').ACL;

acl = new ACL({
  'owner': ['write', 'read', 'update'],
  '*': ['read']
});
```

### assert

Check if given role has access to action

`acl.assert('owner', 'write');`

`-> true`

`acl.assert('public', 'write');`

`-> false`

### grant

Grant access to given role to actions after initializing ACL. 

Example:
```
acl.grant({
  'owner': ['delete'],
  'admin': ['*']
});
```

### revoke

Revokes all access from given roles.

Example:

```
acl.revoke(['owner', 'user', 'tester']);
acl.assert('owner', 'delete');
```
`-> false`