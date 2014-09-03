using System.Collections.Generic;
using NUnit.Framework;
using Sodium;

namespace Tests
{
  [TestFixture]
  public class PasswordHashTest
  {
    [Test]
    public void HashSalsa208Sha256Test()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
      const long OPS_LIMIT = 481326;
      const int MEM_LIMIT = 7256678;

      var hash = PasswordHash.HashSalsa208Sha256(PASSWORD, OPS_LIMIT, MEM_LIMIT);

      Assert.IsTrue(PasswordHash.HashSalsa208Sha256Verify(hash, PASSWORD));
    }

    [Test]
    public void HashSalsa208Sha256InteractiveTest()
    {
        const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
        var hash = PasswordHash.HashSalsa208Sha256(PASSWORD, HashSalsa208Sha256Limit.Interactive);

        Assert.IsTrue(PasswordHash.HashSalsa208Sha256Verify(hash, PASSWORD));
    }

    [Test]
    public void HashSalsa208Sha256SensitiveTest()
    {
        const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
        var hash = PasswordHash.HashSalsa208Sha256(PASSWORD, HashSalsa208Sha256Limit.Sensitive);

        Assert.IsTrue(PasswordHash.HashSalsa208Sha256Verify(hash, PASSWORD));
    }

    [Test]
    public void HashSalsa208Sha256VerifyTest()
    {
      const int OUTPUT = 1;
      const int PASS = 0;
      var tests = new List<string[]>{
        new[] {"^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg nrDFal+Jxl3,2`#^tFSu%v_+7iYse8-cCkNf!tD=KrW)", "$7$B6....1....75gBMAGwfFWZqBdyF3WdTQnWdUsuTiWjG1fF9c1jiSD$tc8RoB3.Em3/zNgMLWo2u00oGIoTyJv4fl3Fl8Tix72"},
        new[] {"bl72h6#y<':MFRZ>B IA1=NRkCKS%W8`1I.2uQxJN0g)N N aTt^4K!Iw5r H6;crDsv^a55j9tsk'/GqweZn;cdk6+F_St6:#*=?ZCD_lw>.", "$7$A6....3....Iahc6qM0.UQJHVgE4h9oa1/4OWlWLm9CCtfguvz6bQD$QnXCo3M7nIqtry2WKsUZ5gQ.mY0wAlJu.WUhtE8vF66"},
        new[] {"Py >e.5b+tLo@rL`dC2k@eJ&4eVl!W=JJ4+k&mAt@gt',FS1JjqKW3aq21:]^kna`mde7kVkN5NrpKUptu)@4*b&?BE_sJMG1=&@`3GBCV]Wg7xwgo7x3El", "$7$96..../....f6bEusKt79kK4wdYN0ki2nw4bJQ7P3rN6k3BSigsK/D$Dsvuw7vXj5xijmrb/NOhdgoyK/OiSIYv88cEtl9Cik7"},
        new[] {"2vj;Um]FKOL27oam(:Uo8+UmSTvb1FD*h?jk_,S=;RDgF-$Fjk?]9yvfxe@fN^!NN(Cuml?+2Raa", "$7$86....I....7XwIxLtCx4VphmFeUa6OGuGJrFaIaYzDiLNu/tyUPhD$U3q5GCEqCWxMwh.YQHDJrlg7FIZgViv9pcXE3h1vg61"},
        new[] {"CT=[9uUoGav,J`kU+348tA50ue#sL:ABZ3QgF+r[#vh:tTOiL>s8tv%,Jeo]jH/_4^i(*jD-_ku[9Ko[=86 06V", "$7$A6....2....R3.bjH6YS9wz9z8Jsj.3weGQ3J80ZZElGw2oVux1TP6$i5u6lFzXDHaIgYEICinLD6WNaovbiXP8SnLrDRdKgA9"},
        new[] {"J#wNn`hDgOpTHNI.w^1a70%f,.9V_m038H_JIJQln`vdWnn/rmILR?9H5g(+`;@H(2VosN9Fgk[WEjaBr'yB9Q19-imNa04[Mk5kvGcSn-TV", "$7$B6....1....Dj1y.4mF1J9XmT/6IDskYdCLaPFJTq9xcCwXQ1DpT92$92/hYfZLRq1nTLyIz.uc/dC6wLqwnsoqpkadrCXusm6"},
        new[] {"j4BS38Asa;p)[K+9TY!3YDj<LK-`nLVXQw9%*QfM", "$7$B6....1....5Ods8mojVwXJq4AywF/uI9BdMSiJ/zT8hQP/4cB68VC$nk4ExHNXJ802froj51/1wJTrSZvTIyyK7PecOxRRaz0"},
        new[] {"M.R>Qw+!qJb]>pP :_.9`dxM9k [eR7Y!yL-3)sNs[R,j_/^ TH=5ny'15>6UXWcQW^6D%XCsO[vN[%ReA-`tV1vW(Nt*0KVK#]45P_A", "$7$B6....1....D/eyk8N5y6Z8YVQEsw521cTx.9zzLuK7YDs1KMMh.o4$alfW8ZbsUWnXc.vqon2zoljVk24Tt1.IsCuo2KurvS2"},
        new[] {"K3S=KyH#)36_?]LxeR8QNKw6X=gFb'ai$C%29V* tyh^Wo$TN-#Q4qkmtTCf0LLb.^E$0uykkP", "$7$B6....1....CuBuU97xgAage8whp/JNKobo0TFbsORGVbfcQIefyP8$aqalP.XofGViB8EPLONqHma8vs1xc9uTIMYh9CgE.S8"},
        new[] {"Y0!?iQa9M%5ekffW(`", "$7$A6....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5"},
      };

      foreach (var test in tests) {
        Assert.IsTrue(PasswordHash.HashSalsa208Sha256Verify(test[OUTPUT], test[PASS]));
      }
    }
  }
}
