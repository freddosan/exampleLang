package org.mal_lang.kvmlang.test;

import core.Attacker;
import core.AttackStep;
import org.junit.jupiter.api.Test;


public class SystemTakeOverTest extends KVMLangTest{

    private static class SystemTakeOverModel {
         /**---First model without activated defenses---*/

        /**Instances & Hypervisor */
        public final Instance instance1 = new Instance("instance1");
        public final Instance instance2 = new Instance("instance2");

        public final QemuKVM hypervisor1 = new QemuKVM("hypervisor1", false);


        /**DATA */
        public final Data data1 = new Data("data1", false);
        public final Data data2 = new Data("data2", false);
       

        /**Applications*/
        public final Application application1 = new Application("application1");
        public final Application application2 = new Application("application2");

        /**System*/
        public final System system1 = new System("system1");
        public final NovaService novaCLI1 = new NovaService("novaCLI1");

        /**---Second model with activated defense---*/

        /**Instances & Hypervisor */
        public final Instance instance3 = new Instance("instance3");
        public final Instance instance4 = new Instance("instance4");

        public final QemuKVM hypervisor2 = new QemuKVM("hypervisor2", false);


        /**DATA */
        public final Data encData1 = new Data("encData1", false);
        public final Data encData2 = new Data("encData2", false);


        public final HardwareMemoryEncryption datacreds1 = new HardwareMemoryEncryption("datacreds1");
        public final HardwareMemoryEncryption datacreds2 = new HardwareMemoryEncryption("datacreds2");
       

        /**Applications*/
        public final Application application3 = new Application("application3");
        public final Application application4 = new Application("application4");

        /**System*/
        public final System system2 = new System("system2");
        public final NovaService novaCLI2 = new NovaService("novaCLI2");
       
        public SystemTakeOverModel() {
            /**---First model without defenses---*/

             /**SYSTEM */
             system1.addHypervisor(hypervisor1);

             /**Instances & Hypervisor */
             hypervisor1.addSysExecutedInstances(instance1);
             hypervisor1.addSysExecutedInstances(instance2);
             
            
             /**DATA */
             instance1.addContainedData(data1);
             instance2.addContainedData(data2);
             //To show that the data of the instance could reside on the host.
             system1.addSysData(data1);
             system1.addSysData(data2);
             /**Applications tied to instances*/
             instance1.addGuestSysExecutedApps(application1);
             instance2.addGuestSysExecutedApps(application2);
             hypervisor1.addInstanceMGMT(novaCLI1);


             /**---Second model with defenses---*/

             /**SYSTEM */
             system2.addHypervisor(hypervisor2);

             /**Instances & Hypervisor */
             hypervisor2.addSysExecutedInstances(instance3);
             hypervisor2.addSysExecutedInstances(instance4);
             
            
             /**DATA */
             encData1.addSecureVirtualization(datacreds1);
             encData2.addSecureVirtualization(datacreds2);
             instance3.addContainedData(encData1);
             instance4.addContainedData(encData2);
             //To show that the data of the instance could reside on the host.
             system2.addSysData(encData1);
             system2.addSysData(encData2);
             /**Applications tied to instances*/
             instance3.addGuestSysExecutedApps(application3);
             instance4.addGuestSysExecutedApps(application4);
             hypervisor2.addInstanceMGMT(novaCLI2);
            


        }
        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }


    }


    @Test
    public void testHostTakeOverReadData() {
    printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new SystemTakeOverModel();

    var attacker = new Attacker();
    model.addAttacker(attacker,model.system1.connect);
    model.addAttacker(attacker,model.system1.authenticate);
    model.addAttacker(attacker,model.system1.fullAccess);
    model.addAttacker(attacker,model.system1._machineAccess);

    attacker.attack();


    model.system1.fullAccess.assertCompromisedInstantaneously();
    model.system1._machineAccess.assertCompromisedInstantaneously();
    model.system1.denialOfService.assertCompromisedInstantaneously();
    
    model.data1.read.assertCompromisedInstantaneously();
    model.data2.read.assertCompromisedInstantaneously();

  }

  @Test
    public void testHostTakeOverUseCli() {
    printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new SystemTakeOverModel();

    var attacker = new Attacker();
    model.addAttacker(attacker,model.system1.connect);
    model.addAttacker(attacker,model.system1.authenticate);
    model.addAttacker(attacker,model.system1.attemptGainFullAccess);


    model.addAttacker(attacker,model.novaCLI1.fullAccess);
    model.addAttacker(attacker,model.novaCLI1._machineAccess);
    attacker.attack();


    model.system1.fullAccess.assertCompromisedInstantaneously();
    model.system1._machineAccess.assertCompromisedInstantaneously();
    model.system1.denialOfService.assertCompromisedInstantaneously();
    
    model.data1.read.assertCompromisedInstantaneously();
    model.data2.read.assertCompromisedInstantaneously();
    model.novaCLI1.attemptUseCLI.assertCompromisedInstantaneously();
    //model.instance1.delete.assertCompromisedInstantaneously();

  }

  @Test
  public void testHostMemoryEncryptionActive() {
  printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
  var model = new SystemTakeOverModel();

  var attacker = new Attacker();
  model.addAttacker(attacker,model.system2.connect);
  model.addAttacker(attacker,model.system2.authenticate);
  model.addAttacker(attacker,model.system2.fullAccess);
  model.addAttacker(attacker,model.system2._machineAccess);

  attacker.attack();


  model.system2.fullAccess.assertCompromisedInstantaneously();
  model.system2._machineAccess.assertCompromisedInstantaneously();
  model.system2.denialOfService.assertCompromisedInstantaneously();
  
  model.encData1.read.assertUncompromised();
  model.encData2.read.assertUncompromised();
  

}

  
    
}