using System.Text;
using Sodium;
using NUnit.Framework;

namespace Tests
{
  [TestFixture]
  public class PasswordHashTest
  {
    [Test]
    public void HashSalsa208Sha256Test()
    {
      string passhex = "a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae065577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02c08da232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6f58d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6";
      string salthex = "5541fbc995d5c197ba290346d2c559dedf405cf97e5f95482143202f9e74f5c2";
      long opsLimit = 481326;
      int memLimit = 7256678;

      string actual = PasswordHash.HashSalsa208Sha256(passhex, salthex, opsLimit, memLimit);

      Assert.AreEqual("8D40F5F8C6A1791204F03E19A98CD74F918B6E331B39CFC2415E5014D7738B7BB0A83551FB14A035E07FDD4DC0C60C1A6822AC253918979F6324FF0C87CBA75D3B91F88F41CA5414A0F152BDC4D636F42AB2250AFD058C19EC31A3374D1BD7133289BF21513FF67CBF8482E626AEE9864C58FD05F9EA02E508A10182B7D838", actual);
    }

    [Test]
    public void HashSalsa208Sha256VerifyTest()
    {
      int output = 0;
      int pass = 1;
      string[,] tests = {
        {"^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg nrDFal+Jxl3,2`#^tFSu%v_+7iYse8-cCkNf!tD=KrW)", "$7$B6....1....75gBMAGwfFWZqBdyF3WdTQnWdUsuTiWjG1fF9c1jiSD$tc8RoB3.Em3/zNgMLWo2u00oGIoTyJv4fl3Fl8Tix72"},
        {"bl72h6#y<':MFRZ>B IA1=NRkCKS%W8`1I.2uQxJN0g)N N aTt^4K!Iw5r H6;crDsv^a55j9tsk'/GqweZn;cdk6+F_St6:#*=?ZCD_lw>.", "$7$A6....3....Iahc6qM0.UQJHVgE4h9oa1/4OWlWLm9CCtfguvz6bQD$QnXCo3M7nIqtry2WKsUZ5gQ.mY0wAlJu.WUhtE8vF66"},
        {"Py >e.5b+tLo@rL`dC2k@eJ&4eVl!W=JJ4+k&mAt@gt',FS1JjqKW3aq21:]^kna`mde7kVkN5NrpKUptu)@4*b&?BE_sJMG1=&@`3GBCV]Wg7xwgo7x3El", "$7$96..../....f6bEusKt79kK4wdYN0ki2nw4bJQ7P3rN6k3BSigsK/D$Dsvuw7vXj5xijmrb/NOhdgoyK/OiSIYv88cEtl9Cik7"},
        {"2vj;Um]FKOL27oam(:Uo8+UmSTvb1FD*h?jk_,S=;RDgF-$Fjk?]9yvfxe@fN^!NN(Cuml?+2Raa", "$7$86....I....7XwIxLtCx4VphmFeUa6OGuGJrFaIaYzDiLNu/tyUPhD$U3q5GCEqCWxMwh.YQHDJrlg7FIZgViv9pcXE3h1vg61"},
        {"CT=[9uUoGav,J`kU+348tA50ue#sL:ABZ3QgF+r[#vh:tTOiL>s8tv%,Jeo]jH/_4^i(*jD-_ku[9Ko[=86 06V", "$7$A6....2....R3.bjH6YS9wz9z8Jsj.3weGQ3J80ZZElGw2oVux1TP6$i5u6lFzXDHaIgYEICinLD6WNaovbiXP8SnLrDRdKgA9"},
        {"J#wNn`hDgOpTHNI.w^1a70%f,.9V_m038H_JIJQln`vdWnn/rmILR?9H5g(+`;@H(2VosN9Fgk[WEjaBr'yB9Q19-imNa04[Mk5kvGcSn-TV", "$7$B6....1....Dj1y.4mF1J9XmT/6IDskYdCLaPFJTq9xcCwXQ1DpT92$92/hYfZLRq1nTLyIz.uc/dC6wLqwnsoqpkadrCXusm6"},
        {"j4BS38Asa;p)[K+9TY!3YDj<LK-`nLVXQw9%*QfM", "$7$B6....1....5Ods8mojVwXJq4AywF/uI9BdMSiJ/zT8hQP/4cB68VC$nk4ExHNXJ802froj51/1wJTrSZvTIyyK7PecOxRRaz0"},
        {"M.R>Qw+!qJb]>pP :_.9`dxM9k [eR7Y!yL-3)sNs[R,j_/^ TH=5ny'15>6UXWcQW^6D%XCsO[vN[%ReA-`tV1vW(Nt*0KVK#]45P_A", "$7$B6....1....D/eyk8N5y6Z8YVQEsw521cTx.9zzLuK7YDs1KMMh.o4$alfW8ZbsUWnXc.vqon2zoljVk24Tt1.IsCuo2KurvS2"},
        {"K3S=KyH#)36_?]LxeR8QNKw6X=gFb'ai$C%29V* tyh^Wo$TN-#Q4qkmtTCf0LLb.^E$0uykkP", "$7$B6....1....CuBuU97xgAage8whp/JNKobo0TFbsORGVbfcQIefyP8$aqalP.XofGViB8EPLONqHma8vs1xc9uTIMYh9CgE.S8"},
        {"Y0!?iQa9M%5ekffW(`", "$7$A6....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5"},
      };

      foreach (var test in tests) {
        Assert.IsTrue(PasswordHash.HashSalsa208Sha256Verify(test[output].ToString(), test[pass].ToString()));
      }

    }
  }
}

