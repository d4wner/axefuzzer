<!--
   _____               ___________                                 
  /  _  \ ___  ___ ____\_   _____/_ __________________ ___________ 
 /  /_\  \\  \/  // __ \|    __)|  |  \___   /\___   // __ \_  __ \
/    |    \>    <\  ___/|     \ |  |  //    /  /    /\  ___/|  | \/
\____|__  /__/\_ \\___  >___  / |____//_____ \/_____ \\___  >__|   
        \/      \/    \/    \/              \/      \/    \/       

   [+..............AxeFuzzer.............+]
   [+..........Powered by demon..........+]
   [+............version  4.0............+]       
  
    我还是很喜欢你，
    就像居合细雪，初见季节。
    愿你燕返长夜，
    身后花开无邪。                 
-->
<body style="background-image:url('https://s1.ax1x.com/2017/11/24/WMtKg.jpg')">
<table border="1">

  <caption>
  <pre><h3><strong>细の雪---{{title}}</strong></h3></pre>
  </caption>

<tr>
%for row_name in row_names:
<td>
{{row_name}}
</td>
%end
</tr>
%for row in rows:
  <tr>
  %for col in row:
    <td>{{!col}}</td>
  %end
  </tr>
%end
</table>
</body>