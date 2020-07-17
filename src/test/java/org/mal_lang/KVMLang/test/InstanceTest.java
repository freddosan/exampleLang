package org.mal_lang.kvmlang.test;

import core.Attacker;
import core.AttackStep;
import org.junit.jupiter.api.Test;

public class InstanceTest extends KVMLangTest{

    private static class InstanceTestModel {
        public final Instance instance = new Instance("instance");

        public InstanceTestModel() {

        }

        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
  }

  @Test
  
  public void testNoAuthenticate() {
    printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new InstanceTestModel();

    var attacker = new Attacker();
    model.addAttacker(attacker,model.instance.connect);
    attacker.attack();

    
    model.instance.authenticatedAccess.assertUncompromised();
    model.instance.fullAccess.assertUncompromised();
}

public void testConnectAndAuthenticate() {
    printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new InstanceTestModel();

    var attacker = new Attacker();
    model.addAttacker(attacker,model.instance.connect);
    model.addAttacker(attacker,model.instance.authenticate);
    attacker.attack();

    model.instance.authenticatedAccess.assertCompromisedInstantaneously();
    model.instance.fullAccess.assertCompromisedInstantaneously();
  
    
}




    
}