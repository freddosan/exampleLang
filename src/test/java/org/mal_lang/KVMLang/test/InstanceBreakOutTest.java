package org.mal_lang.kvmlang.test;

import core.Attacker;
import core.AttackStep;
import org.junit.jupiter.api.Test;

public class InstanceBreakOutTest extends KVMLangTest{

    private static class InstanceBreakOutModel {
        /**Instances & Hypervisor */
        public final Instance instance1 = new Instance("instance1");
        public final Instance instance2 = new Instance("instance2");

        public final QemuKVM hypervisor = new QemuKVM("hypervisor");

        /**DATA */
        public final Data encdata1 = new Data("encData1", false);
        public final Data encdata2 = new Data("encData2", false);


        /**Applications*/
        public final Application application1 = new Application("application1");
        public final Application application2 = new Application("application2");

        /**System*/
        public final System system = new System("system");
        public final HardwareMemoryEncryption datacreds1 = new HardwareMemoryEncryption("datacreds1");
        public final HardwareMemoryEncryption datacreds2 = new HardwareMemoryEncryption("datacreds2");




        public InstanceBreakOutModel() {
            //Kanske byta namn: hypervisor-> add Instance. 
            

            /**SYSTEM */
            system.addHypervisor(hypervisor);

             /**Instances & Hypervisor */
             //instance.addHypervisor(hypervisor);
            hypervisor.addSysExecutedInstances(instance1);
            hypervisor.addSysExecutedInstances(instance2);

            /**DATA */
            encdata1.addEncryptCreds(datacreds1);
            encdata2.addEncryptCreds(datacreds2);

            instance1.addContainedData(encdata1);
            instance2.addContainedData(encdata2);

             /**Applications tied to instances*/
             instance1.addGuestSysExecutedApps(application1);
             instance2.addGuestSysExecutedApps(application2);
        }

        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
  }
    
  @Test
  public void testFetchDatafromInstance1() {


  }


}