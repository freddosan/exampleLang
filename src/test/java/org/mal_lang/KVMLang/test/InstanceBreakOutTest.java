package org.mal_lang.kvmlang.test;

import core.Attacker;
import core.AttackStep;
import org.junit.jupiter.api.Test;

public class InstanceBreakOutTest extends KVMLangTest{

    private static class InstanceBreakOutModel {
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
        public final Application application3 = new Application("application1");
        public final Application application4 = new Application("application2");

        /**System*/
        public final System system2 = new System("system");
        public final NovaService novaCLI = new NovaService("novaCLI");
        public final HardwareMemoryEncryption datacreds3 = new HardwareMemoryEncryption("datacreds3");
        public final HardwareMemoryEncryption datacreds4 = new HardwareMemoryEncryption("datacreds4");
        
        //Mandetory accesscontrol
        public final SELinux sVirt = new SELinux("sVirt");
        


        public InstanceBreakOutModel() {

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
            hypervisor2.addInstanceMGMT(novaCLI);
           
        }

        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
  }
    
  @Test
  public void testFetchDatafromInstance1() {
    printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new InstanceBreakOutModel();

    var attacker = new Attacker();
    model.addAttacker(attacker,model.instance1.connect);
    model.addAttacker(attacker,model.instance1.authenticate);
    model.addAttacker(attacker,model.datacreds1.use);
    attacker.attack();

    
    model.instance1.authenticatedAccess.assertCompromisedInstantaneously();
    model.instance1.fullAccess.assertCompromisedInstantaneously();
    //model.instance1.containedData.attemptRead.assertCompromisedInstantaneously();
    model.encdata1.read.assertCompromisedInstantaneously();
    model.encdata2.read.assertUncompromised();
  }

  @Test
  public void testInstance1BreakOut() {
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
  public void testInstance3BreakoutFailPatchAndSvirt() {
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
    /**Breakout Complete */
    //Data from first instance is compromised(Access to instance, however the data to the second instance is uncompromised). 
    model.encdata4.read.assertUncompromised();
    //NovaCliTest
    
  }


  



}