package org.mal_lang.kvmlang.test;

import core.Attacker;
import core.AttackStep;
import org.junit.jupiter.api.Test;

public class NetworkTest extends KVMLangTest {
    
    private static class simpleNetworkTestModel {
        /*
        Network D <--> Application

        Attacker's entry point: NetworkD.access
        */
        
        public final Network netD = new Network("NetworkD");
        public final Application app1 = new Application("Application1");
        
        public simpleNetworkTestModel() {
            // Create associations
            netD.addApplications(app1);
 
        }
        

        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
        public void assertModel() {
            // Make assertions
            app1.networkConnect.assertCompromisedInstantaneously();    
        }

    }

    @Test
    public void simpleNetworksTest() {
      printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
      //Create the model
      var model = new simpleNetworkTestModel();
      // Create attacker
      var atk = new Attacker();
      model.addAttacker(atk,model.netD.access);
      atk.attack();
      // Assert model
      model.assertModel();
    }
}