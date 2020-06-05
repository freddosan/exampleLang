package org.mal_lang.kvmlang.test;

import core.Attacker;
import core.AttackStep;
import org.junit.jupiter.api.Test;

public class SystemTest extends KVMLangTest {

    private static class SystemTestModel {
        public final System system = new System("system");

        public SystemTestModel() {

        }

        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
  }

  @Test
    public void testNoAuthenticate() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new SystemTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.system.connect);
        attacker.attack();

        
        model.system.attemptGainFullAccess.assertUncompromised();
        model.system.fullAccess.assertUncompromised();
    }

    @Test
    public void testConnectAndAuthenticate() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new SystemTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.system.connect);
        model.addAttacker(attacker,model.system.authenticate);
        attacker.attack();

        model.system.attemptGainFullAccess.assertCompromisedInstantaneously();
        model.system.fullAccess.assertCompromisedInstantaneously();
        model.system._machineAccess.assertCompromisedInstantaneously();
    }
    
}