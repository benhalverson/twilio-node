var expect = require('chai').expect;
var twilio = require('../index');
var jwt = require('jsonwebtoken');


describe('AccessToken', function() {
  var accountSid = 'ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  var keySid = 'SKb5aed9ca12bf5890f37930e63cad6d38';

  describe('constructor', function() {
    var initWithoutIndex = function(index) {
      return function() {
        var constructorArgs = [accountSid, keySid, 'secret'];
        constructorArgs[index] = undefined;

        // add context
        constructorArgs.unshift({});
        new (Function.prototype.bind.apply(twilio.AccessToken, constructorArgs));
      };
    };
    it('should require accountSid', function() {
      var error = new Error('accountSid is required');
      var initWithoutIndex = function() { throw error };
      expect(initWithoutIndex).to.throw(error);
    });
    it('should require keySid', function() {
      var error = new Error('keySid is required');
      var initWithoutIndex = function() { throw error };
      expect(initWithoutIndex).to.throw(error);
    });
    it('should require secret', function() {
      var error = new Error('secret is required');
      var initWithoutIndex = function() { throw error };
      expect(initWithoutIndex).to.throw(error);
    });
  });


  describe('generate', function() {
    it('should generate the correct headers', function() {
      var token = new twilio.AccessToken(accountSid, keySid, 'aTBl1PhJnykIjWll4TOiXKtD1ugxiz6f');
      var decoded = jwt.decode(token.toJwt(), {complete: true});

      expect(decoded.header).to.equal({
        cty: 'twilio-fpa;v=1',
        typ: 'JWT',
        alg: 'HS256'
      });
    });

    it('should accept different algorithsm', function() {
      var validateAlg = function(alg) {
        var token = new twilio.AccessToken(accountSid, keySid, 'secret');
        var decoded = jwt.decode(token.toJwt(alg), {
          complete: true,
          algorithms: twilio.AccessToken.ALGORITHMS
        });
        expect(decoded.header.alg).to.equal(alg);
      };

      validateAlg('HS256');
      validateAlg('HS384');
      validateAlg('HS512');
    });

    it('should throw on invalid algorithm', function() {
      var generateWithAlg = function(alg) {
        return function() {
          new twilio.AccessToken(accountSid, keySid, 'secret').toJwt(alg);
        };
      };

      expect(generateWithAlg('unknown'))
          .to.throw(new Error('Algorithm not supported. ' +
                  'Allowed values are HS256, HS384, HS512'));
    });

    it('should create a token without any grants', function() {
      var token = new twilio.AccessToken(accountSid, keySid, 'secret');
      token.identity = 'ID@example.com';

      var decoded = jwt.verify(token.toJwt(), 'secret');
      expect(decoded.jti.indexOf(keySid)).to.be(0);
      expect(decoded.iss).to.be(keySid);
      expect(decoded.sub).to.be(accountSid);
      expect(decoded.exp - decoded.iat).to.be(3600);
      expect(decoded.grants).to.equal({
        identity: 'ID@example.com'
      });
    });

    it('should accept nbf', function() {
      var nbf = Math.floor(Date.now() / 1000);
      var token = new twilio.AccessToken(accountSid, keySid, 'secret', { nbf: nbf });
      token.identity = 'ID@example.com';

      var decoded = jwt.verify(token.toJwt(), 'secret');
      expect(decoded.jti.indexOf(keySid)).to.be(0);
      expect(decoded.iss).to.be(keySid);
      expect(decoded.sub).to.be(accountSid);
      expect(decoded.nbf).to.be(nbf);
      var delta = Math.abs(decoded.nbf - Math.floor(Date.now() / 1000));
      expect(delta).to.be.less.than(10);

      expect(decoded.exp - decoded.iat).to.be(3600);
      expect(decoded.grants).to.equal({
        identity: 'ID@example.com'
      });
    })

    it('should accept user defined ttl', function() {
      var token = new twilio.AccessToken(accountSid, keySid, 'secret');
      token.ttl = 100;
      token.identity = 'ID@example.com';

      var decoded = jwt.verify(token.toJwt(), 'secret');
      expect(decoded.exp - decoded.iat).to.be(100);
    });

    it('should create token with ip messaging grant', function() {
      var token = new twilio.AccessToken(accountSid, keySid, 'secret');
      token.identity = 'ID@example.com';

      var grant = new twilio.AccessToken.IpMessagingGrant();
      grant.serviceSid = 'SRaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      grant.endpointId = 'endpointId';
      grant.pushCredentialSid = 'CRaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      grant.deploymentRoleSid = 'RLaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      token.addGrant(grant);

      var decoded = jwt.verify(token.toJwt(), 'secret');
      expect(decoded.grants).to.equal({
        identity: 'ID@example.com',
        ip_messaging: {
          service_sid: 'SRaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          deployment_role_sid: 'RLaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          endpoint_id: 'endpointId',
          push_credential_sid: 'CRaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        }
      });
    });

    it('should create token with conversation grant', function() {
      var token = new twilio.AccessToken(accountSid, keySid, 'secret');
      token.identity = 'ID@example.com';

      var grant = new twilio.AccessToken.ConversationsGrant();
      grant.configurationProfileSid = 'CPaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      token.addGrant(grant);

      var decoded = jwt.verify(token.toJwt(), 'secret');
      expect(decoded.grants).to.equal({
        identity: 'ID@example.com',
        rtc: {
          configuration_profile_sid: 'CPaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        }
      });
    });

    it('should create token with multiple grants', function() {
      var token = new twilio.AccessToken(accountSid, keySid, 'secret');
      token.identity = 'ID@example.com';

      var grant = new twilio.AccessToken.IpMessagingGrant();
      grant.serviceSid = 'SRaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      grant.endpointId = 'endpointId';
      grant.pushCredentialSid = 'CRaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      grant.deploymentRoleSid = 'RLaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      token.addGrant(grant);

      grant = new twilio.AccessToken.ConversationsGrant();
      grant.configurationProfileSid = 'CPaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      token.addGrant(grant);

      var decoded = jwt.verify(token.toJwt(), 'secret');
      expect(decoded.grants).to.equal({
        identity: 'ID@example.com',
        ip_messaging: {
          service_sid: 'SRaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          deployment_role_sid: 'RLaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          endpoint_id: 'endpointId',
          push_credential_sid: 'CRaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        },
        rtc: {
          configuration_profile_sid: 'CPaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        }
      });
    });

    describe('IpMessagingGrant', function() {
      describe('toPayload', function() {
        it('should only populate set properties', function() {
          var grant = new twilio.AccessToken.IpMessagingGrant();
          expect(grant.toPayload()).to.equal({});

          grant.deploymentRoleSid = 'RLaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
          expect(grant.toPayload()).to.equal({
            deployment_role_sid: 'RLaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
          });

          grant.serviceSid = 'SRaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
          expect(grant.toPayload()).to.equal({
            service_sid: 'SRaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            deployment_role_sid: 'RLaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
          });

          grant.endpointId = 'endpointId';
          expect(grant.toPayload()).to.equal({
            service_sid: 'SRaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            deployment_role_sid: 'RLaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            endpoint_id: 'endpointId'
          });

          grant.endpointId = undefined;
          grant.pushCredentialSid = 'CRaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
          expect(grant.toPayload()).to.equal({
            service_sid: 'SRaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            deployment_role_sid: 'RLaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            push_credential_sid: 'CRaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
          });

          grant.endpointId = 'endpointId';
          expect(grant.toPayload()).to.equal({
            service_sid: 'SRaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            deployment_role_sid: 'RLaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            endpoint_id: 'endpointId',
            push_credential_sid: 'CRaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
          });
        });
      });
    });

    describe('ConversationGrant', function() {
      it('should only populate set properties', function() {
        var grant = new twilio.AccessToken.ConversationsGrant();
        expect(grant.toPayload()).to.equal({});

        grant.configurationProfileSid = 'CPsid';
        expect(grant.toPayload()).to.equal({
          configuration_profile_sid: 'CPsid'
        });
      });
    });
  });

});
