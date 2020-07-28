package org.mal_lang.kvmlang.test;

import core.Attacker;
import core.AttackStep;
import org.junit.jupiter.api.Test;

public class InstanceTest extends KVMLangTest{

    private static class InstanceTestModel {
        public final Instance instance = new Instance("instance");
        public final QemuKVM virtulization = new QemuKVM("virtulization", false);

        public InstanceTestModel() {
            instance.addHypervisor(virtulization);
            virtulization.addSysExecutedInstances(instance);

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

    @Test
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
    @Test
    public void testDeviceEmulationExploit() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new InstanceTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.instance.connect);
        model.addAttacker(attacker,model.instance.authenticate);
        attacker.attack();

        model.instance.authenticatedAccess.assertCompromisedInstantaneously();
        model.instance.fullAccess.assertCompromisedInstantaneously();
        model.instance.deviceEmulationExploit.assertCompromisedInstantaneously();
        model.instance.improperMemoryBounds.assertCompromisedInstantaneously();
        model.instance.outOfBoundsRead.assertCompromisedInstantaneously();
        model.instance.nullPointerDereference.assertCompromisedInstantaneously();
        //Next step
        model.instance.attemptNullPointerDereference.assertCompromisedInstantaneously();
        model.instance.attemptExploitBufferOverflow.assertCompromisedInstantaneously();
        model.instance.attemptExploitOutOfBoundsRead.assertCompromisedInstantaneously();
        model.instance.venomFDC.assertCompromisedInstantaneously();
        

    }


    @Test
    public void testDeviceEmulationExploitBufferOverflow() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new InstanceTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.instance.connect);
        model.addAttacker(attacker,model.instance.authenticate);
        model.addAttacker(attacker,model.virtulization.bufferOverflow);
        attacker.attack();

        model.instance.authenticatedAccess.assertCompromisedInstantaneously();
        model.instance.fullAccess.assertCompromisedInstantaneously();
        model.instance.deviceEmulationExploit.assertCompromisedInstantaneously();

        model.instance.improperMemoryBounds.assertCompromisedInstantaneously();
        
        model.instance.attemptExploitBufferOverflow.assertCompromisedInstantaneously();
        model.virtulization.bufferOverflow.assertCompromisedInstantaneously(); 

    }


    @Test
    public void testSRWD() {
        printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
        var model = new InstanceTestModel();

        var attacker = new Attacker();
        model.addAttacker(attacker,model.instance.connect);
        model.addAttacker(attacker,model.instance.authenticate);
        attacker.attack();

        model.instance.authenticatedAccess.assertCompromisedInstantaneously();
        model.instance.fullAccess.assertCompromisedInstantaneously();
        model.instance.stop.assertCompromisedInstantaneously();
        model.instance.read.assertCompromisedInstantaneously();
        model.instance.write.assertCompromisedInstantaneously();
        model.instance.delete.assertCompromisedInstantaneously();
        model.instance.deny.assertCompromisedInstantaneously();

    }




    
}