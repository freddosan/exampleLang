package org.mal_lang.kvmlang.test;

import core.Attacker;
import core.AttackStep;
import org.junit.jupiter.api.Test;

public class NovaServiceTest extends KVMLangTest {
    
    private static class NovaServiceModel { 
        
        public final NovaService novaCLI = new NovaService("novaCLI");


        public NovaServiceModel(){
             
        }

        public void addAttacker(Attacker attacker, AttackStep attackpoint) {
            attacker.addAttackPoint(attackpoint);
        }
    }
    
    @Test
    public void testNovaServiceConnect() {
      printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
      var model = new NovaServiceModel();
  
      var attacker = new Attacker();

      
      model.addAttacker(attacker,model.novaCLI.fullAccess);
      model.addAttacker(attacker,model.novaCLI._machineAccess);
      attacker.attack();
  
      //NovaCli
      model.novaCLI.fullAccess.assertCompromisedInstantaneously();
      model.novaCLI._machineAccess.assertCompromisedInstantaneously();
      model.novaCLI.attemptUseCLI.assertCompromisedInstantaneously();
  
    }

    @Test
    public void testNovaServiceNoFullaccess() {
      printTestName(Thread.currentThread().getStackTrace()[1].getMethodName());
      var model = new NovaServiceModel();
  
      var attacker = new Attacker();

      
      //model.addAttacker(attacker,model.novaCLI.fullAccess);
      model.addAttacker(attacker,model.novaCLI._machineAccess);
      attacker.attack();
  
      //NovaCli
      model.novaCLI.fullAccess.assertUncompromised();
      model.novaCLI._machineAccess.assertCompromisedInstantaneously();
      model.novaCLI.attemptUseCLI.assertUncompromised();
  
    }
}
