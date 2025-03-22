import { View, StyleSheet } from 'react-native';
import Signin from './Signin';

export default function RootLayout() {
  return (
    <View style={styles.container}>
      <Signin />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
});
