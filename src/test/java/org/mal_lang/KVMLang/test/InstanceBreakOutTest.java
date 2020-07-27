package org.mal_lang.kvmlang.test;

import core.Attacker;
import core.AttackStep;
import org.junit.jupiter.api.Test;

public class InstanceBreakOutTest extends KVMLangTest{

    private static class InstanceBreakOutModel {
      /**First model has Hardware Memory encryption active.
       * Second model has Svirt and Patching active.
       * Third model has no defenses active
       * */  
      
      /**Instances & Hypervisor */
      public final Instance instance1 = new Instance("instance1");
      public final Instance instance2 = new Instance("instance2");

      public final QemuKVM hypervisor = new QemuKVM("hypervisor", false);


        /**DATA */
        public final Data encdata1 = new Data("encData1", false);
        public final Data encdata2 = new Data("encData2", false);
        public final Data data3 = new Data("data3", false);
       

        /**Applications*/
        public final Application application1 = new Application("application1");
        public final Application application2 = new Application("application2");

        /**System*/
        public final System system = new System("system");
        public final NovaService novaCLI = new NovaService("novaCLI");
        public final HardwareMemoryEncryption datacreds1 = new HardwareMemoryEncryption("datacreds1");
        public final HardwareMemoryEncryption datacreds2 = new HardwareMemoryEncryption("datacreds2");
        
        /**---Second model with activated defenses (Patched hypervisor & Svirt)---*/
        
        /**Instances & Hypervisor */
        public final Instance instance3 = new Instance("instance3");
        public final Instance instance4 = new Instance("instance4");
        public final QemuKVM hypervisor2 = new QemuKVM("hypervisor2", true);
        /**DATA */
        public final Data encdata3 = new Data("encData3", false);
        public final Data encdata4 = new Data("encData4", false);
       

        /**Applications*/
        public final Application application3 = new Application("application3");
        public final Application application4 = new Application("application4");

        /**System*/
        public final System system2 = new System("system");
        public final NovaService novaCLI2 = new NovaService("novaCLI2");
        public final HardwareMemoryEncryption datacreds3 = new HardwareMemoryEncryption("datacreds3");
        public final HardwareMemoryEncryption datacreds4 = new HardwareMemoryEncryption("datacreds4");
        
        //Mandetory accesscontrol
        public final SELinux sVirt = new SELinux("sVirt");


        /**---Third model without activated defenses---*/

        /**Instances & Hypervisor */
        public final Instance instance5 = new Instance("instance5");
        public final Instance instance6 = new Instance("instance6");

        public final QemuKVM hypervisor3 = new QemuKVM("hypervisor3", false);


        /**DATA */
        public final Data data5 = new Data("data5", false);
        public final Data data6 = new Data("data6", false);
       

        /**Applications*/
        public final Application application5 = new Application("application5");
        public final Application application6 = new Application("application6");

        /**System*/
        public final System system3 = new System("system3");
        public final NovaService novaCLI3 = new NovaService("novaCLI3");
       

        public InstanceBreakOutModel() {

          /**---First model with activated memory encryption---*/
            /**SYSTEM */
            system.addHypervisor(hypervisor);

             /**Instances & Hypervisor */
            hypervisor.addSysExecutedInstances(instance1);
            hypervisor.addSysExecutedInstances(instance2);
            
            /**DATA */
            encdata1.addSecureVirtualization(datacreds1);
            encdata2.addSecureVirtualization(datacreds2);

            instance1.addContainedData(encdata1);
            instance2.addContainedData(encdata2);
            //To show that the data of the instance could reside on the host.
            system.addSysData(encdata2);
             /**Applications tied to instances*/
             instance1.addGuestSysExecutedApps(application1);
             instance2.addGuestSysExecutedApps(application2);
            // Instance mgmt
            hypervisor.addInstanceMGMT(novaCLI);

        /**---Second model with activated defenses---*/
            /**SYSTEM */
            system2.addHypervisor(hypervisor2);

            /**Instances & Hypervisor */
            hypervisor2.addSysExecutedInstances(instance3);
            hypervisor2.addSysExecutedInstances(instance4);
            //Hypervisor protection.
            hypervisor2.addSvirt(sVirt);
           
            /**DATA */
            encdata3.addSecureVirtualization(datacreds3);
            encdata4.addSecureVirtualization(datacreds4);

            instance3.addContainedData(encdata3);
            instance4.addContainedData(encdata4);
            //To show that the data of the instance could reside on the host.
            system2.addSysData(encdata4);
            /**Applications tied to instances*/
            instance3.addGuestSysExecutedApps(application3);
            instance4.addGuestSysExecutedApps(application4);
            hypervisor2.addInstanceMGMT(novaCLI2);

             /**-----Third model without defenses-----*/

             /**SYSTEM */
            system3.addHypervisor(hypervisor3);

            /**Instances & Hypervisor */
            hypervisor3.addSysExecutedInstances(instance5);
            hypervisor3.addSysExecutedInstances(instance6);
            
           
            /**DATA */
            instance5.addContainedData(data5);
            instance6.addContainedData(data6);
            //To show that the data of the instance could reside on the host.
            system3.addSysData(data5);
            system3.addSysData(data6);
            /**Applications tied to instances*/
            instance3.addGuestSysExecutedApps(application5);
            instance4.addGuestSysExecutedApps(application6);
            hypervisor3.addInstanceMGMT(novaCLI3);
           
        }

        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
  }
    
  @Test
  public void testFetchDatafromInstance1_TC4() {
    printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new InstanceBreakOutModel();

    var attacker = new Attacker();
    model.addAttacker(attacker,model.instance1.connect);
    model.addAttacker(attacker,model.instance1.authenticate);
    model.addAttacker(attacker,model.datacreds1.use);
    attacker.attack();

    
    model.instance1.authenticatedAccess.assertCompromisedInstantaneously();
    model.instance1.fullAccess.assertCompromisedInstantaneously();
    model.encdata1.read.assertCompromisedInstantaneously();
    model.encdata2.read.assertUncompromised();
  }

  @Test
  public void testInstance1BreakOut_TC5() {
    printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new InstanceBreakOutModel();

    var attacker = new Attacker();
    model.addAttacker(attacker,model.instance1.connect);
    model.addAttacker(attacker,model.instance1.authenticate);
    model.addAttacker(attacker,model.datacreds1.use);
    attacker.attack();

    //Instance traverse
    model.instance1.authenticatedAccess.assertCompromisedInstantaneously();
    model.instance1.fullAccess.assertCompromisedInstantaneously();
    model.encdata1.read.assertCompromisedInstantaneously();
    model.instance1.deviceEmulationExploit.assertCompromisedInstantaneously();
    model.instance1.improperMemoryBounds.assertCompromisedInstantaneously();
    model.instance1.venomFDC.assertCompromisedInstantaneously();
    //Hypervisor traverse
    model.hypervisor.attemptVenomFDC.assertCompromisedInstantaneously();
    model.hypervisor.venomExploit.assertCompromisedInstantaneously();
    
    
    //SystemTraverse
    model.system.fullAccess.assertCompromisedInstantaneously();
    model.system._machineAccess.assertCompromisedInstantaneously();
    /**Breakout Complete */
    //Data from first instance is compromised(Access to instance, however the data to the second instance is uncompromised). 
    model.encdata2.read.assertUncompromised();
  }

  @Test
  public void testInstance3BreakoutFailPatchAndSvirt_TC6() {
    printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new InstanceBreakOutModel();

    var attacker = new Attacker();
    model.addAttacker(attacker,model.instance3.connect);
    model.addAttacker(attacker,model.instance3.authenticate);
    model.addAttacker(attacker,model.datacreds3.use);
    attacker.attack();

    //Instance traverse
    model.instance3.authenticatedAccess.assertCompromisedInstantaneously();
    model.instance3.fullAccess.assertCompromisedInstantaneously();
    model.encdata3.read.assertCompromisedInstantaneously();
    model.instance3.deviceEmulationExploit.assertCompromisedInstantaneously();
    model.instance3.improperMemoryBounds.assertCompromisedInstantaneously();
    model.instance3.venomFDC.assertCompromisedInstantaneously();
    //Hypervisor traverse
    model.hypervisor2.attemptVenomFDC.assertCompromisedInstantaneously();
    model.hypervisor2.venomExploit.assertUncompromised();
    
    //SystemTraverse
    model.system2.fullAccess.assertUncompromised();
    model.system2._machineAccess.assertUncompromised();
    /**Breakout Failed */
    //Data from first instance is compromised(Access to instance, however the data to the second instance is uncompromised). 
    model.encdata4.read.assertUncompromised();
  }

  @Test
  public void testModel3BreakOut_TC7() {
    printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new InstanceBreakOutModel();

    var attacker = new Attacker();
    model.addAttacker(attacker,model.instance5.connect);
    model.addAttacker(attacker,model.instance5.authenticate);
    attacker.attack();

    //Instance traverse
    model.instance5.authenticatedAccess.assertCompromisedInstantaneously();
    model.instance5.fullAccess.assertCompromisedInstantaneously();
    model.data5.read.assertCompromisedInstantaneously();
    model.instance5.deviceEmulationExploit.assertCompromisedInstantaneously();
    model.instance5.improperMemoryBounds.assertCompromisedInstantaneously();
    model.instance5.venomFDC.assertCompromisedInstantaneously();
    //Hypervisor traverse
    model.hypervisor3.attemptVenomFDC.assertCompromisedInstantaneously();
    model.hypervisor3.venomExploit.assertCompromisedInstantaneously();
    
    
    //SystemTraverse
    model.system3.fullAccess.assertCompromisedInstantaneously();
    model.system3._machineAccess.assertCompromisedInstantaneously();
    /**Breakout Complete */
    //Data from first instance is compromised(Access to instance, however the data to the second instance is also compromised due to Data is not encrypted). 
    model.data6.read.assertCompromisedInstantaneously();
  }

 



}