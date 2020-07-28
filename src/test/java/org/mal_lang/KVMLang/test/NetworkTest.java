package org.mal_lang.kvmlang.test;

import core.Attacker;
import core.AttackStep;
import org.junit.jupiter.api.Test;

public class NetworkTest extends KVMLangTest {
    
    private static class NetworkTestModel {
        /*
        Network D <--> Application
        Attacker's entry point: NetworkD.access
        */
        
        public final Network netD = new Network("NetworkD");
        public final Application app1 = new Application("Application1");
        public final Data data1 = new Data("data1", false);
        
        public NetworkTestModel() {
            // Create associations
            netD.addApplications(app1);
            app1.addContainedData(data1);
 
        }
        

        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
        

    }

    @Test
    public void simpleNetworksTest() {
      printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
      //Create the model
      var model = new NetworkTestModel();
      // Create attacker
      var atk = new Attacker();
      model.addAttacker(atk,model.netD.access);

      atk.attack();
      // Assert model
      model.app1.networkConnect.assertCompromisedInstantaneously();
    }

    @Test
    public void physicalNetworkAttack_TC12() {
      printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
      //Create the model
      var model = new NetworkTestModel();
      // Create attacker
      var atk = new Attacker();
      model.addAttacker(atk,model.netD.physicalAccess);

      atk.attack();
      // Assert model
      model.netD.denialOfService.assertCompromisedInstantaneously();
      model.app1.deny.assertCompromisedInstantaneously();
      model.data1.deny.assertCompromisedInstantaneously();
    
    }

    @Test
    public void networkAttackToApplication_TC13() {
      printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
      //Create the model
      var model = new NetworkTestModel();
      // Create attacker
      var atk = new Attacker();
      model.addAttacker(atk,model.netD.access);
      model.addAttacker(atk,model.app1.authenticate);

      atk.attack();
      // Access to network application
      model.app1.networkConnect.assertCompromisedInstantaneously();
      model.app1.networkAccess.assertCompromisedInstantaneously();
      model.app1.fullAccess.assertCompromisedInstantaneously();
      //Access to data
      model.data1.attemptRead.assertCompromisedInstantaneously();
      model.data1.attemptAccess.assertCompromisedInstantaneously();
      model.data1.deny.assertCompromisedInstantaneously();
      
    }





}