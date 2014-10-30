var should = require('chai').should();
var ACL = require('..').ACL;

describe('Access Roles', function () {
  var acl;

  before(function () {
    acl = new ACL({
      'owner': ['write', 'read', 'update'],
      '*': ['read']
    });
  });

  it('should be possible to make ACL assertions agains roles and actions', function () {
    acl.assert('owner', 'write').should.equal(true);
    acl.assert('public', 'write').should.equal(false);
    acl.assert('public', 'read').should.equal(true);
    acl.assert('owner', 'delete').should.equal(false);
    acl.assert('read').should.equal(true);
    acl.assert('write').should.equal(false);
  });

  it('should be possible to add more rules with .grant', function () {
    acl.grant({
      'owner': ['delete'],
      'admin': ['*']
    });
    acl.assert('admin', 'write').should.equal(true);
    acl.assert('admin', 'read').should.equal(true);
    acl.assert('admin', 'nonexisting').should.equal(true);
    acl.assert('owner', 'delete').should.equal(true);
  });

  it('should be possible to grant and revoke access', function () {
    acl.grant({
      'tester': ['read', 'write'],
      'owner': ['read', 'write', 'delete']
    });
    acl.assert('owner', 'delete').should.equal(true);
    acl.revoke('owner');
    acl.assert('owner', 'delete').should.equal(false);
    acl.grant({
      'owner': ['delete']
    });
    acl.assert('owner', 'delete').should.equal(true);
    acl.revoke(['owner', 'user', 'tester']);
    acl.assert('owner', 'delete').should.equal(false);
  });

  it('should recognice the "*" selector in roles and permissions', function () {
    acl.grant({
      'test': '*'
    });
    acl.assert('test', 'anything').should.equal(true);
    acl.assert('test2', 'anything').should.equal(false);
    acl.grant({
      '*': 'abolish'
    });
    acl.assert('anyone', 'abolish').should.equal(true);
    acl.assert('anyone', 'destroye').should.equal(false);
  });
});