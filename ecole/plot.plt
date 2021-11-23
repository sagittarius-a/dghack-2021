set term wxt persist size 1440,900
set title "Benchmark Python vs Rust"

set xlabel "Seconds elapsed"
set ylabel "Tries"

set xrange [ 1 : 26 ]

set grid xtics ytics mxtics mytics

# set logscale y
set style fill noborder transparent solid 0.6 

plot \
     "solution-rs/rust-stat-16.txt" using 1:2 with filledcurves above y=0 linecolor rgb "light-red" title "Rust 16 mutations", \
     "solution-rs/rust-stat-128.txt" using 1:2 with filledcurves above y=0 linecolor rgb "dark-red" title "Rust 128 mutations", \
     "python-stat-128.txt" using 1:2 with filledcurves above y=0 linecolor rgb "light-blue" title "Python 128 mutations", \
     "python-stat-16.txt" using 1:2 with filledcurves above y=0 linecolor rgb "dark-blue" title "Python 16 mutations"
